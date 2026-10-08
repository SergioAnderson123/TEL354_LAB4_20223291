import yaml
import json
import requests
import asyncio
import aiohttp
import itertools

# Constantes
# IP del controlador Floodlight (localhost si el script corre en la VM del controlador)
CONTROLLER_IP = "127.0.0.1"
# Número de protocolo IP según el protocolo del servicio
PROTO_NUM = {"TCP": "0x06", "UDP": "0x11"}
# Contador para generar handlers únicos (nunca repite, aunque se borren conexiones)
HANDLER_IDS = itertools.count(1)


# Clases
class Student:
    """Alumno identificado por su MAC, que la asocia el servicio NAC."""
    _next_code = 1  # contador para asignar un código si el yaml no trae uno

    def __init__(self, name, mac, code=None):
        self.name = name
        self.mac = mac
        self.code = code if code else f"A{Student._next_code:03d}"
        Student._next_code += 1

    def __str__(self):
        return f"{self.code} | {self.name} | {self.mac}"


class Service:
    """Servicio expuesto por un servidor (nombre, protocolo, puerto)."""

    def __init__(self, name, protocol, port):
        self.name = name
        self.protocol = protocol.upper()
        self.port = port

    def __str__(self):
        return f"{self.name} ({self.protocol}/{self.port})"


class Server:
    """Servidor con IP y lista de objetos Service."""

    def __init__(self, name, ip, services):
        self.name = name
        self.ip = ip
        # services llega como lista de dicts {name, protocol, port}
        self.services = [Service(s["name"], s["protocol"], s["port"]) for s in services]

    def get_service(self, service_name):
        """Devuelve el Service con ese nombre o None."""
        for s in self.services:
            if s.name == service_name:
                return s
        return None


class Course:
    """Curso con estado, nombres de alumnos y servidores permitidos."""

    def __init__(self, name, state, students, servers, code=None):
        self.name = name
        self.code = code
        self.state = state                 # "ACTIVE" o "INACTIVE"
        self.students = list(students)     # lista de nombres de alumnos
        # servers llega como [{name, allowed_services: [...]}]
        # se guarda como {nombre_servidor: [servicios permitidos]}
        self.servers = {x["name"]: list(x["allowed_services"]) for x in servers}

    def allows(self, student_name, server_name, service_name):
        """Devuelve True si el curso autoriza al alumno al servicio X del servidor Y."""
        return (self.state == "ACTIVE"
                and student_name in self.students
                and service_name in self.servers.get(server_name, []))


class Connection:
    """Conexión proactiva de un alumno a un servicio de un servidor, identificada por un handler."""

    def __init__(self, handler, student, server, service, flow_names):
        self.handler = handler            # identificador de la conexión
        self.student = student            # objeto Student
        self.server = server              # objeto Server
        self.service = service            # objeto Service
        self.flow_names = flow_names      # nombres de los flows instalados (para borrarlos)

    def __str__(self):
        return (f"{self.handler} | {self.student.name} -> "
                f"{self.server.name} {self.service}")


# Carga de datos
def load_data(filename):
    with open(filename, "r") as file:
        data = yaml.safe_load(file)
    students = [ Student(x["name"], x["mac"]) for x in data["students"] ]
    servers = [ Server(y["name"], y["ip"], y["services"]) for y in data["servers"] ]
    courses = [ Course(z["name"], z["state"], z["students"], z["servers"], z["code"]) for z in data["courses"] ]
    return students, servers, courses

# API del controlador Floodlight

def get_attachment_point(controller_ip, mac):
    endpoint = '/wm/device/'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(
        url,
        params={'mac': mac}
    )
    result, = response.json()
    attachment_points = result.get("attachmentPoint", [])

    if not attachment_points:
        return None, None

    attachment_point, = attachment_points
    return attachment_point["switchDPID"], attachment_point["port"]


def get_route(controller_ip, src_mac, dst_mac):
    src_sw_dpid, src_sw_port = get_attachment_point(controller_ip, src_mac)
    dst_sw_dpid, dst_sw_port = get_attachment_point(controller_ip, dst_mac)
    endpoint = f'/wm/topology/route/{src_sw_dpid}/{src_sw_port}/{dst_sw_dpid}/{dst_sw_port}/json'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(url)
    return response.json()


def get_device(controller_ip, **filters):
    """Consulta /wm/device/ filtrando por mac= o ipv4=. Devuelve el primer dispositivo o None."""
    url = 'http://' + controller_ip + ':8080/wm/device/'
    devices = requests.get(url, params=filters).json()
    return devices[0] if devices else None


# Utilidades
def is_authorized(student, server, service, courses):
    """Devuelve True si algún curso ACTIVE matricula al alumno y permite el servicio en ese servidor."""
    return any(c.allows(student.name, server.name, service.name) for c in courses)


def valid_mac(mac):
    """Valida el formato de una MAC: 6 pares hexadecimales separados por ':'."""
    parts = mac.split(":")
    return len(parts) == 6 and all(len(p) == 2 and all(ch in "0123456789abcdefABCDEF" for ch in p) for p in parts)


def find_by(items, attr, value):
    """Busca el primer objeto de la lista cuyo atributo coincide, sin distinguir mayúsculas."""
    for it in items:
        if str(getattr(it, attr)).lower() == str(value).lower():
            return it
    return None


# Flows asíncronos Static Flow Pusher
def _pusher_url(controller_ip):
    """Devuelve la URL del Static Flow Pusher del controlador."""
    return "http://" + controller_ip + ":8080/wm/staticflowpusher/json"


def _hops(route):
    """Convierte la ruta de Floodlight (2 entradas por switch) en [(dpid, puerto_in, puerto_out)]."""
    hops = []
    for i in range(0, len(route), 2):
        hops.append((route[i]["switch"],
                     route[i]["port"]["portNumber"],       # puerto por donde entra
                     route[i + 1]["port"]["portNumber"]))  # puerto por donde sale
    return hops


def _build_flows(handler, hops, student, student_ip, server, server_mac, service):
    """Arma la lista de flows para ambos sentidos, con match L2, L3 y L4, y ARP."""
    proto = PROTO_NUM[service.protocol]
    l4 = service.protocol.lower()          # "tcp" o "udp" (prefijo de los campos L4)
    flows = []

    for n, (dpid, in_p, out_p) in enumerate(hops):
        base = {"switch": dpid, "active": "true"}
        # IDA (alumno hacia servidor): L2 (MACs), L3 (IPs), L4 (protocolo y puerto destino)
        flows.append({**base, "name": f"{handler}-{n}-ida", "priority": "100",
                      "in_port": str(in_p),
                      "eth_type": "0x0800", "eth_src": student.mac, "eth_dst": server_mac,
                      "ipv4_src": student_ip, "ipv4_dst": server.ip,
                      "ip_proto": proto, f"{l4}_dst": str(service.port),
                      "actions": f"output={out_p}"})
        # VUELTA (servidor hacia alumno): direcciones y puertos invertidos
        flows.append({**base, "name": f"{handler}-{n}-vuelta", "priority": "100",
                      "in_port": str(out_p),
                      "eth_type": "0x0800", "eth_src": server_mac, "eth_dst": student.mac,
                      "ipv4_src": server.ip, "ipv4_dst": student_ip,
                      "ip_proto": proto, f"{l4}_src": str(service.port),
                      "actions": f"output={in_p}"})
        # ARP en ambos sentidos (filtrado por MAC origen de cada host)
        flows.append({**base, "name": f"{handler}-{n}-arp-ida", "priority": "90",
                      "in_port": str(in_p), "eth_type": "0x0806", "eth_src": student.mac,
                      "actions": f"output={out_p}"})
        flows.append({**base, "name": f"{handler}-{n}-arp-vuelta", "priority": "90",
                      "in_port": str(out_p), "eth_type": "0x0806", "eth_src": server_mac,
                      "actions": f"output={in_p}"})
    return flows


async def _push(session, url, flow):
    """Envía un flow (POST) al Static Flow Pusher y devuelve su nombre si se instaló."""
    async with session.post(url, json=flow) as resp:
        data = await resp.json()
        if "pushed" not in data.get("status", "").lower():
            raise RuntimeError(f"{flow['name']}: {data}")
        return flow["name"]


async def build_route(controller_ip, route, handler, student, student_ip, server, server_mac, service):
    """Inserta de forma asíncrona todos los flows de la conexión y devuelve sus nombres."""
    flows = _build_flows(handler, _hops(route), student, student_ip, server, server_mac, service)
    url = _pusher_url(controller_ip)
    async with aiohttp.ClientSession() as session:
        # gather lanza todos los POST a la vez en lugar de uno por uno
        return list(await asyncio.gather(*[_push(session, url, f) for f in flows]))


async def _delete(session, url, name):
    """Borra un flow (DELETE) por su nombre."""
    async with session.delete(url, json={"name": name}) as resp:
        return await resp.json()


async def delete_route(controller_ip, flow_names):
    """Borra de forma asíncrona todos los flows de una conexión."""
    url = _pusher_url(controller_ip)
    async with aiohttp.ClientSession() as session:
        await asyncio.gather(*[_delete(session, url, n) for n in flow_names])


# Menús
def menu():
    """Muestra el menú principal y devuelve la opción elegida."""
    print("\n=== MENÚ PRINCIPAL ===")
    for i, opt in enumerate(["Importar", "Exportar", "Cursos", "Alumnos",
                             "Servidores", "Políticas", "Conexiones", "Salir"], 1):
        print(f"{i}. {opt}")
    return input("Opción: ").strip()


def menu_alumnos(students):
    """Submenú Alumnos: Crear, Listar (con filtro) y Mostrar detalles."""
    while True:
        print("\n--- ALUMNOS ---\n1. Crear\n2. Listar\n3. Mostrar detalles\n4. Volver")
        op = input("Opción: ").strip()
        if op == "1":
            name = input("Nombre: ").strip()
            mac = input("MAC (aa:bb:cc:dd:ee:ff): ").strip()
            if not name or not valid_mac(mac):
                print("Error: nombre vacío o MAC inválida.")
            elif find_by(students, "mac", mac):
                print("Error: ya existe un alumno con esa MAC.")
            else:
                students.append(Student(name, mac))
                print("Alumno creado.")
        elif op == "2":
            filtro = input("Filtrar por nombre (Enter = todos): ").strip().lower()
            for s in students:
                if filtro in s.name.lower():
                    print(s)
        elif op == "3":
            s = find_by(students, "code", input("Código del alumno: ").strip())
            print(f"Código: {s.code}\nNombre: {s.name}\nMAC: {s.mac}" if s else "Alumno no encontrado.")
        elif op == "4":
            return


def menu_cursos(students, courses):
    """Submenú Cursos: Listar, Mostrar detalles y Gestionar alumnos."""
    while True:
        print("\n--- CURSOS ---\n1. Listar\n2. Mostrar detalles\n3. Gestionar alumnos\n4. Volver")
        op = input("Opción: ").strip()
        if op == "1":
            for c in courses:
                print(f"{c.code} | {c.name} | {c.state}")
        elif op in ("2", "3"):
            c = find_by(courses, "code", input("Código del curso: ").strip())
            if not c:
                print("Curso no encontrado.")
                continue
            if op == "2":
                print(f"Código: {c.code}\nNombre: {c.name}\nEstado: {c.state}")
                print("Alumnos:")
                if not c.students:
                    print("  (ninguno)")
                for name in c.students:
                    # c.students guarda nombres; se busca el Student para mostrar código y MAC
                    s = find_by(students, "name", name)
                    print("  -", s if s else f"{name} (no registrado)")
                for srv, svcs in c.servers.items():
                    print(f"Servidor {srv}: servicios {svcs}")
            else:
                accion = input("1. Agregar alumno  2. Eliminar alumno: ").strip()
                s = find_by(students, "name", input("Nombre del alumno: ").strip())
                if not s:
                    print("Alumno no existe.")
                elif accion == "1" and s.name not in c.students:
                    c.students.append(s.name)
                    print("Alumno agregado al curso.")
                elif accion == "2" and s.name in c.students:
                    c.students.remove(s.name)
                    print("Alumno eliminado del curso.")
                else:
                    print("Sin cambios (ya estaba/no estaba en el curso).")
        elif op == "4":
            return


def menu_servidores(servers):
    """Submenú Servidores: Listar y Mostrar servicios."""
    while True:
        print("\n--- SERVIDORES ---\n1. Listar\n2. Mostrar servicios\n3. Volver")
        op = input("Opción: ").strip()
        if op == "1":
            for s in servers:
                print(f"{s.name} | {s.ip}")
        elif op == "2":
            s = find_by(servers, "name", input("Nombre del servidor: ").strip())
            if s:
                print(f"{s.name} ({s.ip})")
                for svc in s.services:
                    print(" -", svc)
            else:
                print("Servidor no encontrado.")
        elif op == "3":
            return


def menu_conexiones(students, servers, courses, connections):
    """Submenú Conexiones: Crear, Listar y Borrar (modo proactivo)."""
    while True:
        print("\n--- CONEXIONES ---\n1. Crear\n2. Listar\n3. Borrar\n4. Volver")
        op = input("Opción: ").strip()

        if op == "1":
            s = find_by(students, "name", input("Nombre del alumno: ").strip())
            srv = find_by(servers, "name", input("Nombre del servidor: ").strip())
            svc = srv.get_service(input("Servicio: ").strip()) if srv else None
            if not (s and srv and svc):
                print("Error: alumno, servidor o servicio inexistente.")
                continue
            # Validación de autorización
            if not is_authorized(s, srv, svc, courses):
                print(f"Error: {s.name} no está autorizado a {svc.name} en {srv.name}.")
                continue
            try:
                # La IP del alumno y la MAC del servidor salen del controlador (/wm/device/)
                dev_s = get_device(CONTROLLER_IP, mac=s.mac)
                dev_srv = get_device(CONTROLLER_IP, ipv4=srv.ip)
                if not dev_s or not dev_s["ipv4"] or not dev_srv:
                    print("Error: el controlador no conoce al host. Haz ping desde H1/H3 primero.")
                    continue
                route = get_route(CONTROLLER_IP, s.mac, dev_srv["mac"][0])
                handler = f"conn{next(HANDLER_IDS)}"
                flow_names = asyncio.run(build_route(
                    CONTROLLER_IP, route, handler, s, dev_s["ipv4"][0], srv, dev_srv["mac"][0], svc))
                connections[handler] = Connection(handler, s, srv, svc, flow_names)
                print(f"Conexión creada. Handler: {handler}")
            except Exception as e:
                print("Error al crear la conexión:", e)

        elif op == "2":
            if not connections:
                print("(sin conexiones)")
            for c in connections.values():
                print(c)

        elif op == "3":
            c = connections.get(input("Handler a borrar: ").strip())
            if not c:
                print("Handler no encontrado.")
            elif not is_authorized(c.student, c.server, c.service, courses):
                # También se valida la autorización al borrar, como pide la guía
                print("Error: el alumno no está autorizado.")
            else:
                try:
                    asyncio.run(delete_route(CONTROLLER_IP, c.flow_names))
                    del connections[c.handler]
                    print("Conexión borrada.")
                except Exception as e:
                    print("Error al borrar la conexión:", e)

        elif op == "4":
            return


# Programa principal
def main():
    students, servers, courses = load_data("database.yaml")
    connections = {}   # handler -> Connection
    while True:
        op = menu()
        if op == "3":
            menu_cursos(students, courses)
        elif op == "4":
            menu_alumnos(students)
        elif op == "5":
            menu_servidores(servers)
        elif op == "7":
            menu_conexiones(students, servers, courses, connections)
        elif op == "8":
            print("Hasta luego.")
            break
        else:
            print("Opción no disponible aún.")


if __name__ == "__main__":
    main()
