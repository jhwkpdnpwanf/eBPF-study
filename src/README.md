# 제목


## 01-Basics

eBPF의 학습을 시작하는 기초 단계로, 간단한 실습을 중심으로 eBPF의 개념과 활용을 소개한다. 대부분 eunomia-bpf 프레임워크 위주의 실습으로 eBPF의 기본적인 사용법과 개발 흐름을 따라가본다.
<br>

### 목차
- [01-Background-of-eBPF](./01-Background-of-eBPF.md) : eBPF의 기초 개념과 동작 배경 설명  

- [02-Tracepoint-Based-Syscall-Hooking](./02-Tracepoint-Based-Syscall-Hooking.md) : tracepoint를 활용한 syscall 후킹 실습  

- [03-Kprobe-Based-Syscall-Hooking](./03-Kprobe-Based-Syscall-Hooking.md) : kprobe를 활용한 syscall 후킹 실습, tracepoint와 차이 비교  

- [04-Fentry-Based-Syscall-Hooking](./01-Basics/04-Fentry-Based-Syscall-Hooking.md ) : Fentry를 활용한 syscall 후킹 실습  

- [05-Uprobe-Based-Function-Call-Capturing](./01-Basics/05-Uprobe-Based-Function-Call-Capturing.md) : uprobe 기반 유저 공간 함수 호출 캡처

- [06-Sigsnoop-with-Hashmap](./01-Basics/06-Sigsnoop-with-Hashmap.md) : Signal snooping 후 Hashmap에 저장 실습


- [07-Capturing-Process-Execution-with-perf-event-array](./01-Basics/07-Capturing-Process-Execution-with-perf-event-array.md) : perf event array를 활용한 프로세스 실행 캡쳐


- [08-Monitoring-Process-Exit-with-Ring-Buffer](./01-Basics/08-Monitoring-Process-Exit-with-Ring-Buffer.md) : ring buffer를 활용한 프로세스 종료 캡쳐


<br>

## 02-Advanced

기초를 넘어선 고급 단계로, 실제 시스템과 응용 프로그램에 eBPF를 적용하는 주제를 다룬다. 특히 libbpf를 중심으로 프로젝트를 구성하고, 다양한 응용 시나리오 속에서 eBPF를 어떻게 결합할 수 있는지 살펴본다. 네트워크, 성능 모니터링, 보안 등 구체적인 사례를 통해 실무적인 활용법을 익히는 것을 목표로 한다.   
<br>

### 목차
- 01   

<br>

## 03-In-Depth

eBPF의 내부 동작 원리와 보안적 관점까지 확장하여 깊이 있게 탐구한다.  
Android 환경에서의 활용, eBPF를 이용한 공격 및 방어 기법, 복잡한 트레이싱 기법 등을 실험한다.  
또한 사용자 공간과 커널 공간의 연계 방식을 심층적으로 분석하며, eBPF의 강력한 기능과 잠재적인 보안 리스크를 함께 이해하는 것을 목표로 한다.  

<br>

### 목차
- 01