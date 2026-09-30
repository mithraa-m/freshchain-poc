"""
Optional MQTT bridge for the FRESHCHAIN POC.

Run a local Mosquitto broker, then:
    python mqtt_bridge.py

The dashboard itself can operate without a broker. This module demonstrates
the intended MQTT/TLS transport path.
"""
import json, ssl, time
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883
TOPIC = "freshchain/FC-NODE-01/telemetry"

def on_connect(client, userdata, flags, reason_code, properties=None):
    print("MQTT connected:", reason_code)
    client.subscribe(TOPIC)

def on_message(client, userdata, msg):
    print("RX", msg.topic, msg.payload.decode())

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="freshchain-dashboard")
client.on_connect = on_connect
client.on_message = on_message

# For production/TLS broker:
# client.tls_set(ca_certs="ca.crt", certfile="client.crt",
#                keyfile="client.key", tls_version=ssl.PROTOCOL_TLS_CLIENT)

client.connect(BROKER, PORT, 60)
print("Listening on", TOPIC)
client.loop_forever()
