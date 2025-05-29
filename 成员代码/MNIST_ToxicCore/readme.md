# MNIST 投毒攻击实验

本项目围绕 MNIST 数据集，运用简单的 MLP 模型开展投毒攻击实验。

## 项目概述

- **模型架构**：使用两层全连接神经网络 (MLP)，针对 MNIST 数据特点优化，能够有效识别手写数字图像
- **数据集**：使用标准 MNIST 数据集，包含 60,000 张训练图像和 10,000 张测试图像
- **预训练模型**：提供了预训练模型下载功能，可通过 `--use_pretrained` 参数加载
- **模型下载链接**：[预训练模型](https://drive.google.com/uc?id=1pHtflNlxmxGMsMxPoHe1ytam1p4H4OUA)
- **数据集链接**：[MNIST 数据集](http://yann.lecun.com/exdb/mnist/)

## 使用方法

1. 安装依赖：
```
pip install torch torchvision numpy gdown
```

2. 运行训练：
```
python main.py --epochs 10 --batch_size 64
```

3. 使用预训练模型：
```
python main.py --use_pretrained
```

## 参数说明

- `--data_root`：数据存储路径，默认 `./data`
- `--log_file`：日志文件路径，默认 `./training_log.txt`
- `--batch_size`：训练批次大小，默认 64
- `--test_batch_size`：测试批次大小，默认 1000
- `--epochs`：训练轮数，默认 10
- `--lr`：学习率，默认 0.01
- `--momentum`：SGD 动量，默认 0.5
- `--seed`：随机种子，默认 42
- `--use_cuda`：是否使用 GPU，默认不使用
- `--use_pretrained`：是否使用预训练模型，默认不使用
- `--pretrained_path`：预训练模型路径，默认 `./pretrained_model.pt`
