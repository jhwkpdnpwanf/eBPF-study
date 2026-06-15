# 제목


## 01-Basics

eBPF의 학습을 시작하는 기초 단계로, 간단한 실습을 중심으로 eBPF의 개념과 활용을 소개한다. 대부분 eunomia-bpf 프레임워크 위주의 실습으로 eBPF의 기본적인 사용법과 개발 흐름을 따라가본다.
<br>

### 목차
- [01-Background-of-eBPF](./01-Basics/01-Background-of-eBPF.md) : eBPF의 기초 개념과 동작 배경 설명  

- [02-Tracepoint-Based-Syscall-Hooking](./01-Basics/02-Tracepoint-Based-Syscall-Hooking.md) : tracepoint를 활용한 syscall 후킹 실습  

- [03-Kprobe-Based-Syscall-Hooking](./01-Basics/03-Kprobe-Based-Syscall-Hooking.md) : kprobe를 활용한 syscall 후킹 실습, tracepoint와 차이 비교  

- [04-Fentry-Based-Syscall-Hooking](./01-Basics/04-Fentry-Based-Syscall-Hooking.md ) : Fentry를 활용한 syscall 후킹 실습  

- [05-Uprobe-Based-Function-Call-Capturing](./01-Basics/05-Uprobe-Based-Function-Call-Capturing.md) : uprobe 기반 유저 공간 함수 호출 캡처

- [06-Sigsnoop-with-Hashmap](./01-Basics/06-Sigsnoop-with-Hashmap.md) : Signal snooping 후 Hashmap에 저장 실습


- [07-Capturing-Process-Execution-with-perf-event-array](./01-Basics/07-Capturing-Process-Execution-with-perf-event-array.md) : perf event array를 활용한 프로세스 실행 캡쳐


- [08-Monitoring-Process-Exit-with-Ring-Buffer](./01-Basics/08-Monitoring-Process-Exit-with-Ring-Buffer.md) : ring buffer를 활용한 프로세스 종료 캡쳐

- [09-Capturing-Scheduling-Latency](./01-Basics/09-Capturing-Scheduling-Latency.md) : runqlat을 활용한 Scheduling 지연 캡쳐 & 시각화


<br>

## 02-Advanced

기초를 넘어선 고급 단계로, 실제 시스템과 응용 프로그램에 eBPF를 적용하는 주제를 다룬다. 특히 libbpf를 중심으로 프로젝트를 구성하고, 다양한 응용 시나리오 속에서 eBPF를 어떻게 결합할 수 있는지 살펴본다. 네트워크, 성능 모니터링, 보안 등 구체적인 사례를 통해 실무적인 활용법을 익히는 것을 목표로 한다.   
<br>

### 목차  

- [00-setting](./02-Advanced/00-setting.md) : Advanced 환경 세팅과 컴파일 방법 & 주의사항

- [01-ebpf-exec-exit-tracer](./02-Advanced/01-ebpf-exec-exit-tracer.md) : libbpf를 사용한 유저공간 프로그램: exec() exit() 함수 추적  

- [02-monitoring-memory-leaks](./02-Advanced/02-monitoring-memory-leaks.md) : memleak을 통한 메모리누수 모니터링

- [03-tcp-connection-latency.md](./02-Advanced/03-tcp-connection-latency.md.md) : tcpconnlat을 활용한 TCP 연결 지연 확인  

- [04-tcp-state-transitions](./02-Advanced/04-tcp-state-transitions.md) : tcpstate를 활용하여 TCP 연결 상태와 TCP RTT 기록

- [05-lsm-network-detection-defense.md](./02-Advanced/05-lsm-network-detection-defense.md) : LSM을 사용한 보안 탐지와 방어   


<br>

## 03-Project

eBPF의 학습 내용을 기반으로 실제 프로젝트에 활용해본다.  


eBPF의 basic 실습과 advanced 실습 내용을 기반으로 실제 시스템 모니터링 도구를 구현해본다.  

<br>

### 목차

- [xtop](https://github.com/jhwkpdnpwanf/xtop) : eBPF 기반 top 확장형 시스템 모니터링 도구