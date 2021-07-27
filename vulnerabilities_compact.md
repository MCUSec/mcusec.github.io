# Vulnerabilities Summary
Written by Wenqiang Li

<span style="color: grey;">Last updated: Jul 25, 2021</span>

## Preface
This page summarizes all of the vulnerabilities discovered by our reseasrch works including [Para-rehosting](https://www.ndss-symposium.org/ndss-paper/from-library-portability-to-para-rehosting-natively-executing-microcontroller-software-on-commodity-hardware/), [&mu;AFL]() and an in-processing one, all of which are under [Prof. Guan](https://guanle.org/)'s supervision.



## Outline

| Target | Bug number | Affected Vendors or Products |
| :--- | ---: | ---: |
| [Mbed OS MQTT](#mbed_os_mqtt) | 1 | ARM Mbed OS |
| [Mbed OS CoAP](#mbed_os_coap) | 2 | ARM Mbed OS |
| [Mbed OS Client Cli](#mbed_os_cli) | 3 | ARM Mbed OS |
| [AWS FreeRTOS MQTT](#freertos_mqtt) | 1 | Amazon FreeRTOS |
| [AWS FreeRTOS MQTTv2](#freertos_mqttv2) | 1 | Amazon FreeRTOS |
| [FreeRTOS FATFS](#freertos_fatfs) | 1 | FreeRTOS |
| [LiteOS MQTT](#liteos_mqtt) | 2 | Huawei LiteOS |
| [LiteOS LWM2M Client](#liteos_lwm2m_client) | 2 | Huawei LiteOS |
| [LwIP](#lwip) | 3 | NXP, STMicroelectronics |
| [STM PLC](#stm_plc) | 9 | STMicroelectronics |
| [uTasker Modbus](#modbus) | 5 | uTasker |
| [NXP SDK USB Driver](#nxp_usb) | 3 | NXP SDK |
| [STM SDK USB Driver](#stm_usb) | 10 | STMicroelectronics SDK |

---