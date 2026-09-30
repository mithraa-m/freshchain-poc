# FRESHCHAIN Complete Laptop POC

This version is intentionally designed as an engineering console rather than a generic AI-style dashboard.

## What is included

1. Sensor telemetry simulation
   - temperature
   - humidity
   - VOC/ripening trend
   - vibration
   - GPS
   - battery
   - tamper input

2. Offline-first behavior
   - switch network OFF
   - records continue to be written locally
   - records are marked unsynced
   - switch network ON and continue recording

3. Integrity
   - SHA-256 chained records
   - sequence-gap checking
   - database-tamper demonstration
   - ECDSA P-256 software signing equivalent to the ATECC608B trust step
   - AES-256-GCM payload encryption

4. Merkle anchoring
   - local Merkle root
   - local EVM-style anchor record
   - Solidity contract included for a real EVM testnet deployment

5. Condition model
   - cumulative thermal exposure
   - humidity penalty flag
   - vibration/shock flag
   - VOC displayed as a trend flag
   - confidence wording: literature-parameterized, not experimentally calibrated

6. Action engine
   - Normal / High / Very High
   - INSPECT / HOLD on integrity failure or tamper
   - reason codes
   - FEFO-style decision support

7. Journey
   - telemetry chart
   - event timeline
   - GPS trace

8. Optional MQTT
   - mqtt_bridge.py
   - compatible with Mosquitto
   - TLS configuration comments included

## Important implementation truth

The laptop cannot physically emulate:
- an ATECC608B secure element
- an LTE radio
- a real SHT40/LIS3DH/VOC/GPS sensor
- solar/PMIC hardware

Instead, the POC implements their software behavior and explicitly labels the boundary. This prevents the demo from claiming hardware that is not actually connected.

The architecture document places MQTT/offline logging/signing/integrity in P0 and Merkle/testnet anchoring in P1.

## Run

PowerShell:

    cd C:\Users\swast\OneDrive\Desktop\FreshChain
    pip install -r requirements.txt
    streamlit run dashboard.py

## Demo sequence

1. Start with Network available = ON.
2. Record 5–10 normal records.
3. Turn Network available = OFF.
4. Record several records.
5. Turn Temperature excursion = ON.
6. Record several records.
7. Turn Tamper event = ON for one record.
8. Open Integrity tab.
9. Click VERIFY INTEGRITY.
10. Create local Merkle anchor.
11. Click Inject database modification.
12. Verify again and show the failed hash/signature check.
13. Open Action View and show INSPECT / HOLD.

For a real testnet:
- deploy contracts/FreshChainAnchor.sol
- replace the local anchor function with web3.py transaction submission
- show the returned transaction hash and public explorer link
- do not label the local POC anchor as a public blockchain transaction
