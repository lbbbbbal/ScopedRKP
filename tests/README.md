# 开发验证

这些工具只存在于源码仓库，不会进入 KernelSU 安装包。

主机策略和脚本测试：

```sh
c++ -std=c++20 -O2 -pthread -Isrc tests/policy_test.cpp -o build/policy_test
./build/policy_test
python tests/test_scope.py
python tests/test_boot.py
```

构建 Android 自建进程测试程序：

```sh
python scripts/build.py --ndk /path/to/ndk --tests
python tests/run_android.py --adb /path/to/adb --serial YOUR_DEVICE
```

Android 测试仅向独立 `/data/local/tmp/scopedrkp_fixture_*` 目录放置测试文件。加载测试的目标 PID 由测试程序自己 `fork` 创建；不接受外部 PID，不连接 Keystore/KeyMint/RKP，不安装模块，不改属性。

测试内容包括动态 GOT 查找、名单隔离、并发更新、11 万次策略重载的内存对照、100 次初载/复用、FD 数量、向量寄存器和 errno 保存、阻塞 read 恢复。当前 fixture 需要设备原始 `ro.boot.hwc=CN`，它不会替设备修改属性。

独立测试通过后仍须区分真实服务和跨设备验证，见仓库根目录 `VALIDATION.md`。
