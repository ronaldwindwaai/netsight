# Traffic Baselines and Anomaly Signals

## Baseline dimensions
Per entity:
- time-of-day;
- day-of-week;
- upload/download;
- connection count;
- destinations;
- application mix;
- protocol mix.

## Context
Different baselines for:
- workstation;
- server;
- CCTV/NVR;
- guest/BYOD;
- backup system;
- network infrastructure.

## Signals
- volume deviation;
- first-seen destination;
- unusual country/ASN;
- unusual app/protocol;
- high upload ratio;
- unusual time;
- unusual DNS rate.

## Poisoning resistance
- exclude confirmed incident periods;
- limit adaptation rate;
- keep robust historic reference windows;
- allow operator "expected behaviour" labels without automatically weakening global policy.

## Output
Anomaly score is evidence, not automatic maliciousness.
