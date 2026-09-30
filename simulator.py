import random
import time
from datetime import datetime


def generate_sensor_data():
    temperature = round(random.uniform(23.0, 27.0), 2)
    humidity = round(random.uniform(60.0, 75.0), 2)
    vibration = round(random.uniform(0.05, 0.25), 2)

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "temperature": temperature,
        "humidity": humidity,
        "vibration": vibration
    }


print("FRESHCHAIN SENSOR SIMULATOR")
print("----------------------------")

for i in range(10):
    data = generate_sensor_data()

    print(
        f"Time: {data['timestamp']} | "
        f"Temp: {data['temperature']} °C | "
        f"Humidity: {data['humidity']} % | "
        f"Vibration: {data['vibration']} g"
    )

    time.sleep(1)