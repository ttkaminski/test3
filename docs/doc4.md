---
id: doc4
title: Model Specifications
sidebar_label: Model Specifications
---






## 1. FlowControl Software Specifications



With purchase of FlowControlXNTM, you receive OVA file required for deployment of the software. Please ensure that the file is available for installation process.

  

Below you will find hardware requirements, in Tab.1, for desired flow limits.



| Raw Flow Capacity           | 30K fps                            | 60K fps                              | 120K fps                              | 250K fps                              |
| --------------------------- | ---------------------------------- | ------------------------------------ | ------------------------------------- | ------------------------------------- |
| vCPU                        | 8-16 x vCPU (4-8 cores per socket) | 16-24 x vCPU (8-12 cores per socket) | 24-32 x vCPU (12-16 cores per socket) | 32-40 x vCPU (16-20 cores per socket) |
| Memory                      | 16-32 GB RAM                       | 32 GB RAM                            | 64 GB RAM                             | 64 GB RAM                             |
| Raw Disk Capacity (System)  | 230 GB SSD                         | 230 GB SSD                           | 230 GB SSD                            | 230 GB SSD                            |
| Raw Disk Capacity (Archive) | 500GB HDD2                         | 1TB HDD2                             | 2TB HDD2                              | 2TB HDD2                              |
| Interface                   | 1x1GB/s Interface                  | 1x1GB/s Interface                    | 1x1GB/s Interface                     | 1x1GB/s Interface                     |

> **Attention**: 
>
> 1. System drive should be located on the SSD partition.
> 2. Supported Hypervisor VMware ESXi 6.5+.
> 3. Please note that all vCPUs should be divided between 2 sockets, e.g for option with 60k FPS, that has 16 vCPUs, there will be 8 vCPUs per socket.



## 2. FlowControl Hardware Specifications