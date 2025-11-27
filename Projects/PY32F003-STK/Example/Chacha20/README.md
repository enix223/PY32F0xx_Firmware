# py32f003x上实现chacha20加密算法

1. 随机生成key
2. 随机生成nonce
3. 实现对字符串: `Hello, World!`的加密
4. 使用相同的key对密文解密
5. 如果解密后与原文一致，则按1秒钟反转LED

## 感谢

* Thanks for Pp3ng, https://github.com/Pp3ng/ChaCha20-Poly1305-AEAD
