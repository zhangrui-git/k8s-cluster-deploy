kubernetes二进制部署笔记  
最后更新：2024-03-06

# 节点基础环境配置
关闭防火墙，关闭swap，关闭selinux  

允许iptables检查桥接流量  
```shell
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
# 配置生效
sysctl --system
```
时间同步  
```shell
yum install chrony -y
systemctl start  chronyd
systemctl enable chronyd
systemctl status chronyd
```

|HostName|IP|Component|OS|
|---|---|---|---|
|k8s-master|172.17.17.2/16|apiserver, controller-manager, scheduler, etcd|CentOS Linux release 7.9|
|k8s-node-1|172.17.17.3/16|kubelet, kube-proxy, docker|CentOS Linux release 7.9|
|k8s-node-2|172.17.17.4/16|kubelet, kube-proxy, docker|CentOS Linux release 7.9|
```shell
# 每台主机都执行
cat >> /etc/hosts << EOF
172.17.17.2 k8s-master
172.17.17.3 k8s-node-1
172.17.17.4 k8s-node-2
EOF
# 对应主机分别执行
hostnamectl set-hostname k8s-master
hostnamectl set-hostname k8s-node-1
hostnamectl set-hostname k8s-node-2
```

# 准备资源

CA证书管理工具：https://github.com/cloudflare/cfssl/releases  
cfssl, cfssljson, cfssl-certinfo

kubernetes组件：https://kubernetes.io/zh-cn/releases/download/  
kubectl, kube-apiserver, kube-controller-manager, kube-scheduler, kubelet, kube-proxy

runc: https://github.com/opencontainers/runc/releases

containerd: https://github.com/containerd/containerd/releases


# etcd安装
### 安装路径 
程序 `/opt/etcd/bin`  
配置 `/opt/etcd/cfg`  
证书 `/opt/etcd/ssl`  
### ca-config.json
```json
{
    "signing": {
        "default": {
            "expiry": "87600h"
        },
        "profiles": {
            "kubernetes": {
                "expiry": "87600h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "server auth",
                    "client auth"
                ]
            }
        }
    }
}
```
### ca-csr.json
```json
{
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Beijing",
            "L": "Beijing"
        }
    ]
}
```
### 生成CA证书
```powershell
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
```
### server-csr.json
```json
{
    "CN": "etcd",
    "hosts": [
        "172.17.17.2",
        "172.17.17.3",
        "172.17.17.4"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Beijing",
            "L": "Beijing"
        }
    ]
}
```
### 签名https证书
```powershell
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json -profile kubernetes server-csr.json | cfssljson -bare server
```
### etcd.service
`/usr/lib/systemd/system/etcd.service`
```ini
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
EnvironmentFile=/opt/etcd/cfg/etcd.conf
ExecStart=/opt/etcd/bin/etcd \
--cert-file=/opt/etcd/ssl/server.pem \
--key-file=/opt/etcd/ssl/server-key.pem \
--peer-cert-file=/opt/etcd/ssl/server.pem \
--peer-key-file=/opt/etcd/ssl/server-key.pem \
--trusted-ca-file=/opt/etcd/ssl/ca.pem \
--peer-trusted-ca-file=/opt/etcd/ssl/ca.pem \
--logger=zap
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```
```shell
systemctl enable etcd
systemctl start etcd
systemctl status etcd
```
### 查看etcd集群状态
```shell
etcdctl --cacert=/opt/etcd/ssl/ca.pem --cert=/opt/etcd/ssl/server.pem --key=/opt/etcd/ssl/server-key.pem --endpoints="https://172.17.17.2:2379" endpoint health
etcdctl --cacert=/opt/etcd/ssl/ca.pem --cert=/opt/etcd/ssl/server.pem --key=/opt/etcd/ssl/server-key.pem --endpoints="https://172.17.17.2:2379" version
```
# Master Node安装
## 安装路径
程序 `/opt/kubernetes/bin`
配置 `/opt/kubernetes/cfg`
证书 `/opt/kubernetes/ssl`
日志 `/opt/kubernetes/logs`
```shell
mkdir -p /opt/kubernetes/{bin,cfg,ssl,logs}
ln -s /opt/kubernetes/bin/kubectl /usr/bin/kubectl
```


## apiserver
### apiserver.conf
```ini
KUBE_APISERVER_OPTS="
--v=2 
--etcd-servers=https://172.17.17.2:2379 
--bind-address=172.17.17.2 
--secure-port=6443 
--advertise-address=172.17.17.2 
--allow-privileged=true 
--service-cluster-ip-range=10.0.0.0/24 
--authorization-mode=RBAC,Node 
--enable-bootstrap-token-auth=true 
--token-auth-file=/opt/kubernetes/cfg/token.csv 
--service-node-port-range=30000-32767 
--kubelet-client-certificate=/opt/kubernetes/ssl/kube-apiserver.pem 
--kubelet-client-key=/opt/kubernetes/ssl/kube-apiserver-key.pem 
--tls-cert-file=/opt/kubernetes/ssl/kube-apiserver.pem 
--tls-private-key-file=/opt/kubernetes/ssl/kube-apiserver-key.pem 
--client-ca-file=/opt/etcd/ssl/ca.pem 
--service-account-key-file=/opt/etcd/ssl/ca-key.pem 
--service-account-issuer=api 
--service-account-signing-key-file=/opt/etcd/ssl/ca-key.pem 
--etcd-cafile=/opt/etcd/ssl/ca.pem 
--etcd-certfile=/opt/etcd/ssl/server.pem 
--etcd-keyfile=/opt/etcd/ssl/server-key.pem 
--requestheader-client-ca-file=/opt/etcd/ssl/ca.pem 
--proxy-client-cert-file=/opt/kubernetes/ssl/kube-apiserver.pem 
--proxy-client-key-file=/opt/kubernetes/ssl/kube-apiserver-key.pem --requestheader-allowed-names=kubernetes 
--requestheader-extra-headers-prefix=X-Remote-Extra- 
--requestheader-group-headers=X-Remote-Group 
--requestheader-username-headers=X-Remote-User 
--enable-aggregator-routing=true 
--audit-log-maxage=30 
--audit-log-maxbackup=3 
--audit-log-maxsize=100 
--audit-log-path=/opt/kubernetes/logs/k8s-audit.log
"
```
### toke.csv
生成token
```shell
head -c 16 /dev/urandom | od -An -t x | tr -d ' '
3ea6477568b0d29f212e1cecbf84d617
```
token,用户名,UID,用户组
```csv
3ea6477568b0d29f212e1cecbf84d617,kubelet-bootstrap,10001,"system:node-bootstrapper"
```
### kube-apiserver-csr.json
```json
{
    "CN": "kube-apiserver",
    "hosts": [
        "localhost",
        "127.0.0.1",
        "172.17.17.2",
        "172.17.17.3",
        "172.17.17.4",
        "kubernetes",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster",
        "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Beijing",
            "L": "Beijing",
            "O": "k8s",
            "OU": "system"
        }
    ]
}
```
### 签名https证书
```powershell
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json -profile kubernetes kube-apiserver-csr.json | cfssljson -bare kube-apiserver
```
### kube-apiserver.service
```ini
[Unit]
Description=Kubernetes API Server
[Service]
EnvironmentFile=/opt/kubernetes/cfg/apiserver.conf
ExecStart=/opt/kubernetes/bin/kube-apiserver $KUBE_APISERVER_OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target
```
```shell
systemctl enable kube-apiserver
systemctl start kube-apiserver
systemctl status kube-apiserver
```


## controller-manager
### controller-manager.conf
```ini
KUBE_CONTROLLER_MANAGER_OPTS="
--v=2 
--leader-elect=true 
--kubeconfig=/opt/kubernetes/cfg/kube-controller-manager.kubeconfig 
--bind-address=127.0.0.1 
--allocate-node-cidrs=true 
--cluster-cidr=10.244.0.0/16 
--service-cluster-ip-range=10.0.0.0/24 
--cluster-signing-cert-file=/opt/etcd/ssl/ca.pem 
--cluster-signing-key-file=/opt/etcd/ssl/ca-key.pem 
--root-ca-file=/opt/etcd/ssl/ca.pem 
--service-account-private-key-file=/opt/etcd/ssl/ca-key.pem 
--cluster-signing-duration=87600h0m0s
"
```
### kube-controller-manager-csr.json
```json
{
    "CN": "kube-controller-manager",
    "hosts": [],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Beijing",
            "L": "Beijing",
            "O": "system:masters",
            "OU": "system"
        }
    ]
}
```
### 生成证书
```powershell
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json -profile kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager
```
### 生成kubeconfig
```shell
KUBE_CONFIG="/opt/kubernetes/cfg/kube-controller-manager.kubeconfig"
KUBE_APISERVER="https://172.17.17.2:6443"
kubectl config set-cluster kubernetes --certificate-authority=/opt/etcd/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials kube-controller-manager --client-certificate=/opt/kubernetes/ssl/kube-controller-manager.pem --client-key=/opt/kubernetes/ssl/kube-controller-manager-key.pem --embed-certs=true --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default --cluster=kubernetes --user=kube-controller-manager --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}
```
### kube-controller-manager.service
```ini
[Unit]
Description=Kubernetes Controller Manager
[Service]
EnvironmentFile=/opt/kubernetes/cfg/controller-manager.conf
ExecStart=/opt/kubernetes/bin/kube-controller-manager $KUBE_CONTROLLER_MANAGER_OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target
```
```shell
systemctl enable kube-controller-manager
systemctl start kube-controller-manager
systemctl status kube-controller-manager
```


## scheduler
### scheduler.conf
```ini
KUBE_SCHEDULER_OPTS="
--v=2 
--leader-elect=true 
--kubeconfig=/opt/kubernetes/cfg/kube-scheduler.kubeconfig 
--bind-address=127.0.0.1
"
```
### kube-scheduler-csr.json
```json
{
    "CN": "kube-scheduler",
    "hosts": [],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Beijing",
            "L": "Beijing",
            "O": "system:masters",
            "OU": "system"
        }
    ]
}
```
### 生成证书
```powershell
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json -profile kubernetes kube-scheduler-csr.json | cfssljson -bare kube-scheduler
```
### 生成kubeconfig
```shell
KUBE_CONFIG="/opt/kubernetes/cfg/kube-scheduler.kubeconfig"
KUBE_APISERVER="https://172.17.17.2:6443"
kubectl config set-cluster kubernetes --certificate-authority=/opt/etcd/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials kube-scheduler --client-certificate=/opt/kubernetes/ssl/kube-scheduler.pem --client-key=/opt/kubernetes/ssl/kube-scheduler-key.pem --embed-certs=true --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default --cluster=kubernetes --user=kube-scheduler --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}
```
### kube-scheduler.service
```ini
[Unit]
Description=Kubernetes Scheduler
[Service]
EnvironmentFile=/opt/kubernetes/cfg/scheduler.conf
ExecStart=/opt/kubernetes/bin/kube-scheduler $KUBE_SCHEDULER_OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target
```
```shell
systemctl enable kube-scheduler
systemctl start kube-scheduler
systemctl status kube-scheduler
```


## kubectl
```shell
# root用户
mkdir -p /root/.kube
```
### kubectl-csr.json
```json
{
    "CN": "kubectl",
    "hosts": [],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Beijing",
            "L": "Beijing",
            "O": "system:masters",
            "OU": "system"
        }
    ]
}
```
### 生成证书
```powershell
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json -profile kubernetes kubectl-csr.json | cfssljson -bare kubectl
```
### 生成kubeconfig
```shell
mkdir /root/.kube
 
KUBE_CONFIG="/root/.kube/config"
KUBE_APISERVER="https://172.17.17.2:6443"
 
kubectl config set-cluster kubernetes --certificate-authority=/opt/etcd/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials cluster-admin --client-certificate=/opt/kubernetes/ssl/kubectl.pem --client-key=/opt/kubernetes/ssl/kubectl-key.pem --embed-certs=true --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default --cluster=kubernetes --user=cluster-admin --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}
```
### 查看集群
```shell
kubectl get cs
```
### 授权 kubelet-bootstrap用户允许请求证书
```shell
kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap
```


# containerd安装
### containerd
https://github.com/containerd/containerd/releases
cri-containerd-1.7.13-xx-xx.tar.gz 包含runc和cni
```shell
tar zxvf cri-containerd-cni-1.7.13-linux-amd64.tar.gz
cp -r ./etc/cni /etc
cp ./etc/crictl.yaml /etc
cp ./etc/systemd/system/containerd.service /etc/systemd/system

cp ./usr/local/sbin/runc /usr/local/sbin
cp ./usr/local/bin/* /usr/local/bin

cp -r ./opt/* /opt
```
导出配置模板
配置比较复杂比较多  
[config.toml](https://github.com/containerd/containerd/blob/main/docs/man/containerd-config.toml.5.md)
```shell
containerd config default > /etc/containerd/config.toml
```
### runc
https://github.com/opencontainers/runc/releases
因为依赖太多，下载官方的runc替换掉containerd包里的runc。
```shell
install -m 755 runc.amd64 /usr/local/sbin/runc

runc -v
# runc version 1.1.12
# commit: v1.1.12-0-g51d5e946
# spec: 1.0.2-dev
# go: go1.20.13
# libseccomp: 2.5.4

systemctl enable containerd
systemctl start containerd
systemctl status containerd
```


# Work Node安装
## 安装路径
```shell
mkdir -p /opt/kubernetes/{bin,cfg,ssl,logs}
ln -s /opt/kubernetes/bin/kubectl /usr/bin/kubectl
```
## kubelet
### kubelet.conf
```ini
KUBELET_OPTS="
--v=2 
--hostname-override=k8s-node-1 需要修改
--kubeconfig=/opt/kubernetes/cfg/kubelet.kubeconfig 
--config=/opt/kubernetes/cfg/kubelet-config.yml 
--bootstrap-kubeconfig=/opt/kubernetes/cfg/bootstrap.kubeconfig 
--cert-dir=/opt/kubernetes/ssl 
--pod-infra-container-image=kubernetes/pause
"
```
### kubelet-config.yaml
[KubeletConfiguration](https://kubernetes.io/zh-cn/docs/reference/config-api/kubelet-config.v1beta1/#kubelet-config-k8s-io-v1beta1-KubeletConfiguration)
```yaml
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: 0.0.0.0
port: 10250
readOnlyPort: 10255
cgroupDriver: cgroupfs
clusterDNS:
  - 10.0.0.2
clusterDomain: cluster.local
failSwapOn: false
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: /opt/kubernetes/ssl/ca.pem
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
evictionHard:
  imagefs.available: 15%
  memory.available: 100Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
maxOpenFiles: 1000000
maxPods: 110
```
### 生成bootstrap.kubeconfig
```shell
KUBE_CONFIG="/opt/kubernetes/cfg/bootstrap.kubeconfig"
KUBE_APISERVER="https://172.17.17.2:6443"
TOKEN="3ea6477568b0d29f212e1cecbf84d617"

kubectl config set-cluster kubernetes --certificate-authority=/opt/kubernetes/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials "kubelet-bootstrap" --token=${TOKEN} --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default --cluster=kubernetes --user="kubelet-bootstrap" --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}
```
### kubelet.service
```ini
[Unit]
Description=Kubernetes Kubelet
After=network.target
[Service]
EnvironmentFile=/opt/kubernetes/cfg/kubelet.conf
ExecStart=/opt/kubernetes/bin/kubelet $KUBELET_OPTS
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```
```shell
mkdir -p /run/containerd
systemctl enable kubelet
systemctl start kubelet
systemctl status kubelet
```
### 批准kubelet证书申请
```shell
kubectl get csr
NAME                                                   AGE     SIGNERNAME                                    REQUESTOR           REQUESTEDDURATION   CONDITION
node-csr-W4NWW1l5bSlH8wc5lbCVipaBZedsvqHCBYUdYW9nqBI   3m17s   kubernetes.io/kube-apiserver-client-kubelet   kubelet-bootstrap   <none>              Pending

kubectl certificate approve [NAME]

kubectl get node
# NAME         STATUS   ROLES    AGE   VERSION
# k8s-node-1   Ready    <none>   27m   v1.29.2
# k8s-node-2   Ready    <none>   21m   v1.29.2
```
## kube-proxy
### kube-proxy-config.yml
[KubeProxyConfiguration](https://kubernetes.io/zh-cn/docs/reference/config-api/kube-proxy-config.v1alpha1/#kubeproxy-config-k8s-io-v1alpha1-KubeProxyConfiguration)
```yaml
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
metricsBindAddress: 0.0.0.0:10249
clientConnection:
  kubeconfig: /opt/kubernetes/cfg/kube-proxy.kubeconfig
hostnameOverride: k8s-node-1
clusterCIDR: 10.244.0.0/16
```
### kube-proxy-csr.json
```json
{
    "CN": "system:kube-proxy",
    "hosts": [],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Beijing",
            "L": "Beijing",
            "O": "system:masters",
            "OU": "system"
        }
    ]
}
```
### 生成证书
```powershell
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json -profile kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy
```
### 生成kube-proxy.kubeconfig
```shell
KUBE_CONFIG="/opt/kubernetes/cfg/kube-proxy.kubeconfig"
KUBE_APISERVER="https://172.17.17.2:6443"
 
kubectl config set-cluster kubernetes --certificate-authority=/opt/kubernetes/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials kube-proxy --client-certificate=/opt/kubernetes/ssl/kube-proxy.pem --client-key=/opt/kubernetes/ssl/kube-proxy-key.pem --embed-certs=true --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default --cluster=kubernetes --user=kube-proxy --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}
```
### kube-proxy.service
```ini
[Unit]
Description=Kubernetes Proxy
After=network.target
[Service]
ExecStart=/opt/kubernetes/bin/kube-proxy --v=2 --config=/opt/kubernetes/cfg/kube-proxy.yaml
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```
```shell
systemctl enable kube-proxy
systemctl start kube-proxy
systemctl status kube-proxy
```