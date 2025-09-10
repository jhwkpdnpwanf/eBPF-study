# Background of eBPF 

### eBPF 간단 소개
- eBPF 는 linux 커널에서 실행되는 샌드박스 기반 프로그램으로, 높은 권한 환경에서도 안전하게 동작한다. 
- 커널의 기능을 안전하고 효율적으로 확장하는데 사용된다.

<br>

### eBPF를 사용하는 이유  
운영 체제 커널은 시스템을 제어하는 강력한 위치에 있기 때문에 모니터링, 보안, 네트워크 기능을 구현하기엔 매우 이상적이다.  

하지만 핵심적인 역할을 하는 만큼, 안정성과 보안에 대해 높은 요구 사항을 필요로 한다. 이러한 이유때문에 운영 체제 수준의 발전 속도는 운영 체제 외부에서 구현되는 기능에 비해 역사적으로 낮았다.  

이러한 한계를 eBPF가 근본적으로 변화시켰다. 샌드박스 프로그램을 운영 체제 내에서 실행할 수 있게 함으로써, 어플리케이션 개발자는 런타임에 eBPF 프로그램을 통해 커널 기능을 확장할 수 있다.  

운영 체제는 eBPF 프로그램을 커널에 로드할 때 검증 엔진을 통해 먼저 안전성을 검사한다. 이 단계에서 무한 루프, 잘못된 메모리 접근, 권한 위반 같은 위험 요소를 사전에 차단한다.

안전성이 보장된 프로그램은 JIT(Just-In-Time) 컴파일러를 통해 eBPF 바이트코드가 곧바로 CPU가 실행할 수 있는 네이티브 머신 코드로 변환된다. 덕분에 해석기(Interpreter)를 거치지 않고도 커널에 직접 작성된 코드처럼 빠른 실행 속도를 얻는 것이다.  

오늘날 eBPF는 네트워킹, 모니터링, 보안, 스케줄러 최적화 등 다양한 사용 사례를 지원하게 되었다.  

간단한 실제 사용 사례는 아래에서 확인해볼 수 있다.  

- Google: eBPF로 보안 감사, 패킷 처리, 성능 모니터링, CPU 스케줄링 최적화 수행
- Netflix: eBPF로 네트워크 분석을 통해 스트리밍 성능과 가용성 보장
- Android: eBPF로 네트워크·전력·리소스 최적화해 성능과 배터리 수명 개선
- S&P Global: eBPF(Cilium)로 멀티클라우드 네트워킹 관리 및 보안 강화
- Shopify: eBPF(Falco)로 침입 탐지 적용해 전자상거래 보안 강화
- Cloudflare: eBPF로 전 세계 웹사이트의 네트워크 관찰·보안·성능 최적화


<br>

### eBPF 프로그램 실행 방식  
eBPF 프로그램은 event-driven 이며 커널이나 어플리케이션이 특정 훅 지점을 지나갈 때 실행된다.  

`syscall`, `function entry/exit`, `kernal trace points`, `network events` 등 eBPF 에서 미리 정의해둔 훅도 존재한다.  

물론 특정 요구 사항에 맞는 predefined hook이 없는 경우에는 kernal probe(`kprobe`)나 user probe (`uprobe`)를 만들어서 커널/사용자 어플리케이션 어느 곳에나 eBPF 프로그램을 첨부할 수 있다.   

<br>

### eBPF 프로그램 작성 방법  
많은 시나리오에서 eBPF는 직접적으로 사용되지 않고,  `Cilium` , `bcc` , `bpftrace` 와 같은 프로젝트를 통해 간접적으로 사용된다.   

해당 프로젝트는 추상화 계층을 제공하기 때문에, 복잡한 eBPF 코드를 작성하지 않고도 intent-based definitions을 선언하면 된다. 그 정의를 바탕으로 적절한 eBPF 프로그램을 자동으로 생성하고 알맞은 훅에 붙여 실행 시켜준다.   

물론 상위 수준의 추상화가 존재하지 않으면 프로그램을 직접 작성 해야한다. 그러한 경우에는 LLVM과 같은 컴파일러를 활용하여 C 코드를 eBPF bytecode 로 컴파일 할 수 있다.   

<br>

### 앞으로 다룰 내용
앞으로 네트워크와 관련된 주제를 중심으로 학습할 예정이다. 간단한 실습들을 바탕으로 eBPF 에 대한 전반적인 이해도를 높이고, TCP connection, Traffic Control, Capturing TCP information 과 같은 주제를 다룰 것이다.   


<br>


## References
- eBPF Introduction: https://ebpf.io/
- Example of using eBPF: https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/0-introduce