/* Sample board definitions file */
/* This file demonstrates the expected format for board definition header files */

#ifndef SAMPLE_BOARD_DEFINITIONS_H
#define SAMPLE_BOARD_DEFINITIONS_H

/* EtherCAT Master definitions */
#define ECAT_MASTER0 0x0
#define ECAT_MASTER1 0x1
#define ECAT_MASTER2 0x2
#define ECAT_MASTER3 0x3

/* Board type definitions */
#define BDTYPE_ECAT_CMN 0x01
#define BDTYPE_ECAT_IO  0x02
#define BDTYPE_ECAT_MOT 0x03
#define BDTYPE_ECAT_SEN 0x04

/* Node ID definitions */
#define NID_SAFETY      (0x7F | BDTYPE_ECAT_CMN << 8)
#define NID_PROT04_00_S (0x04 | BDTYPE_ECAT_IO << 8)
#define NID_PROT04_01_S (0x05 | BDTYPE_ECAT_IO << 8)
#define NID_PROT04_02_S (0x06 | BDTYPE_ECAT_IO << 8)
#define NID_MOTOR_00    (0x10 | BDTYPE_ECAT_MOT << 8)
#define NID_MOTOR_01    (0x11 | BDTYPE_ECAT_MOT << 8)
#define NID_SENSOR_00   (0x20 | BDTYPE_ECAT_SEN << 8)

/* Board address definitions for Master 0 */
#define MA0_SAFETY      ((ECAT_MASTER0 << 30) | (NID_SAFETY * 0x10000))
#define MA0_PROT04_00_S ((ECAT_MASTER0 << 30) | (NID_PROT04_00_S * 0x10000))
#define MA0_PROT04_01_S ((ECAT_MASTER0 << 30) | (NID_PROT04_01_S * 0x10000))
#define MA0_PROT04_02_S ((ECAT_MASTER0 << 30) | (NID_PROT04_02_S * 0x10000))
#define MA0_MOTOR_00    ((ECAT_MASTER0 << 30) | (NID_MOTOR_00 * 0x10000))
#define MA0_MOTOR_01    ((ECAT_MASTER0 << 30) | (NID_MOTOR_01 * 0x10000))
#define MA0_SENSOR_00   ((ECAT_MASTER0 << 30) | (NID_SENSOR_00 * 0x10000))

/* Board address definitions for Master 1 */
#define MA1_SAFETY      ((ECAT_MASTER1 << 30) | (NID_SAFETY * 0x10000))
#define MA1_PROT04_00_S ((ECAT_MASTER1 << 30) | (NID_PROT04_00_S * 0x10000))
#define MA1_MOTOR_00    ((ECAT_MASTER1 << 30) | (NID_MOTOR_00 * 0x10000))

/* Special addresses */
#define MA0_BROADCAST   0x00000000
#define MA1_BROADCAST   0x40000000

#endif /* SAMPLE_BOARD_DEFINITIONS_H */