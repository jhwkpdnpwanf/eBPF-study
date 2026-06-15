# Advanced 환경 세팅  

Advanced 단게 부터는 bpf 코드 뿐만 아니라 이를 제어하기 위한 유저 공간에서의 코드도 함께 제공된다. ebpf 프로그램을 커널에 붙이기 위해 libbpf를 사용하여 컴파일 할 것이다.  

물론 기존 흐름에서는 ecli를 사용하기 때문에 사용자가 직접 유저 공간을 컴파일할 필요가 없지만, 직접 빌드하고 결과를 느껴보는 것이 중요하다고 생각하기 때문에 이렇게 환경을 세팅하게 되었다.  

<br>

### 실행 환경  

- OS : ubuntu server 24.04.03 LTS

<br>

**필수 패키지**

```
sudo apt update
sudo apt install -y clang llvm lld make gcc
sudo apt install -y libbpf-dev libelf-dev zlib1g-dev
sudo apt install -y linux-tools-common linux-tools-$(uname -r) linux-headers-$(uname -r)
```

<br>

**vmlinux.h 준비**  

CO-RE(Core Relocation)을 사용하는 ebpf 프로그램을 사용하기 위해 vmlinux.h를 생성해주어야한다.  

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
위 명령어를 쳐도되고 아래 링크에서 자신에게 맞는 파일을 들고와도 된다.  

- https://github.com/libbpf/vmlinux.h


<br>

### 빌드  

**eBPF 오브젝트 파일 생성**   

eBPF 코드를 BPF전용 바이트코드로 컴파일해준다.  

```bash
clang -target bpf -g -c bootstrap.bpf.c -o bootstrap.bpf.o
```

<br>

**libbpf skeleton 생성**    

생성된 eBPF 오브젝트로부터 libbpf skeleton 헤더를 생성.  
```bash
bpftool gen skeleton bootstrap.bpf.o > bootstrap.skel.h
```

<br>

**유저공간 로더 컴파일**   

유저 공간 코드를 컴파일하여 실행 파일을 생성.  

```bash
clang bootstrap.c -o bootstrap -lbpf -lelf -lz
```

<br>

**실행**   

실행은 sudo로 실행해주어야한다.  

```bash
sudo ./bootstrap
```

<br>

### 추가 주의사항   

**1. WSL 환경에서는 실습을 권장하지 않는다.**

WSL2 환경에서는 BTF 정보와 eBPF 관련 기능이 제한적이다.  
관련 정보도 적을 뿐더러 커스텀 커널을 빌드해야한다.  
커스텀 빌드는 아래 답변에서 찾을 수 있기는 하다.  
- https://gist.github.com/MarioHewardt/5759641727aae880b29c8f715ba4d30f


순서들을 따르더라도 컴파일은 정상적으로 되지만, 로딩 단계에서 오류가 발생하거나 로그가 정상적으로 출력되지 않는 경우가 굉장히 많이 일어나서 개인적으로 권장하지 않는 방식이다.  

이번 스터디에서는 Ubuntu Server를 사용해서 안정적인 환경에서 진행하는 것이 좋을거라 생각한다.  

<br>

**2. VMware 공유 폴더(/mnt/hgfs)에서는 실행에 주의가 필요하다**

Vmare에서는 파일을 옮기기 위해 공유 폴더 기능을 지원한다. 이번 실습에서도 사용을 했었는데, 코드 편집이나 컴파일 자체는 가능하지만 eBPF 오브젝트 로딩과 skeleton 기반 실행 과정에서 오류가 발생했다.  

실제로 eBPF 오브젝트는 정상적으로 생성되지만 실행단계에서는 오류 발생했다. 동일한 코드를 홈 디렉토리에서 컴파일히면 정상 동작했다.  

따라서 공유 폴더는 코드 전달 및 편집 용도로만 사용하고,
빌드와 실행은 홈 디렉토리에서 수행하는 것을 권장한다.  

<br>

**3. bpftool 패키지 설치 방식**

앞으로 진행하면서 제공되는 코드는 대부분 libbpf skeleton 방식을 사용한다. 따라서 ebpf 오브젝트 파일을 통해 유저 공간에서 사용할 수 있는 스켈레톤 헤더파일을 생성해주어야하는데 이때 bpftool이 필요하다.  
 
Ubuntu 24.04부터는 bpftool이 단독 패키지로 제공되지 않고 linux-tools 패키지에 포함되어서 제공된다고 한다.  
따라서 패키지 설치 당시 bpftool를 설치하지 않았던 것이다.  

<br>

**4. CO-RE 사용 시 -g 옵션**  

앞으로의 코드에서 BPF_CORE_READ() 매크로를 사용하게 되는데, 컴파일 시 디버그 정보가 포함되지 않으니 `error: using builtin_preserve_access_index() without -g` 같은 오류가 발생했다.  

-g 옵션을 포함하여 eBPF 코드를 빌드해야 한다.   

<br>

이번 실습을 처음 진행하는 경우, 여러 시행착오로 인해 시작이 많이 늦어질 수 있다. 위 주의 사항을 사전에 인지하고 환경을 구성하면 불필요한 시행착오를 크게 줄일 수 있을 것이다.  