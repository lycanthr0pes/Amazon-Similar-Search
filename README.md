# llama.cpp
```
cd /home/
git clone https://github.com/ggml-org/llama.cpp.git
cd llama.cpp
cmake -B build
cmake --build build --config Release -j 2
```

# Bonsai 8B
```
wget -O Bonsai-8B.gguf \
  https://huggingface.co/prism-ml/Bonsai-8B-gguf/resolve/main/Bonsai-8B.gguf
```

# 起動
```
/home/llama.cpp/build/bin/llama-server \
  -m /home/products/models/Bonsai-8B.gguf \
  --host 127.0.0.1 \
  --port 8080
```
