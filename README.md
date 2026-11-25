# 节点订阅文件

本仓库自动生成并维护节点订阅文件，供 Hiddify / Clash Meta / sing-box 等客户端导入。

## 订阅地址

```text
https://cdn.jsdelivr.net/gh/WOchovy233/hiddify-free-nodes@output/clean_nodes_singbox.json
```

备用地址：

```text
https://raw.githubusercontent.com/WOchovy233/hiddify-free-nodes/output/clean_nodes_singbox.json
```

## 输出文件

| 文件 | 适用客户端 |
|---|---|
| clean_nodes_singbox.json | Hiddify、sing-box |
| clean_nodes.yaml | Clash / Clash Meta / Mihomo |
| clean_nodes.txt | Base64 订阅链接 |
| clean_nodes_plain.txt | 纯链接，方便单条复制 |

## 更新方式

- GitHub Actions 每 12 小时自动运行一次，重新抓取、测速，并覆盖 `output` 分支
- 订阅地址固定不变，客户端点「更新订阅」即可

## 数据来源

节点来自下列公开订阅源，本仓库只做抓取、测速与格式转换：

- ermaozi/get_subscribe
- anaer/Sub
- zhangkaiitugithub/passcro
- chengaopan/AutoMergePublicNodes
- free18/v2ray
- mahdibland/ShadowsocksAggregator
- peasoft/NoMoreWalls
- ripaojiedian/freenode
- awesome-vpn/awesome-vpn
- sunmiao4458/free-proxy-airport

## 说明

- 本仓库只提供订阅文件，不提供任何客户端程序下载
- 节点可用性取决于上游源，测速结果仅代表当次运行时的状态
- 抓取结果会按延迟与稳定性排序，并剔除重复与明文协议节点
