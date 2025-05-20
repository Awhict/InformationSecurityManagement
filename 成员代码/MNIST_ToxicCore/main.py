import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torchvision import datasets, transforms
import numpy as np
import random
import argparse
from datetime import datetime

# 设置随机种子确保可重复性
def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
    os.environ['PYTHONHASHSEED'] = str(seed)

# 简单的MLP模型
class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.fc1 = nn.Linear(28*28, 500)
        self.fc2 = nn.Linear(500, 10)

    def forward(self, x):
        x = x.view(-1, 28*28)
        x = F.relu(self.fc1(x))
        x = self.fc2(x)
        return F.log_softmax(x, dim=1)

# 数据加载与预处理
def load_data(data_root, batch_size, test_batch_size):
    try:
        # 数据转换
        transform = transforms.Compose([
            transforms.ToTensor(),
            transforms.Normalize((0.1307,), (0.3081,))
        ])
        
        # 加载训练集
        train_dataset = datasets.MNIST(
            root=data_root, train=True, download=True, transform=transform
        )
        
        # 加载测试集
        test_dataset = datasets.MNIST(
            root=data_root, train=False, transform=transform
        )
        
        # 创建数据加载器
        train_loader = torch.utils.data.DataLoader(dataset=all_trainset, batch_size=64, shuffle=True, num_workers=4)
        
        test_loader = torch.utils.data.DataLoader(dataset=all_trainset, batch_size=64, shuffle=True, num_workers=4)
        
        return train_loader, test_loader
    
    except Exception as e:
        print(f"数据加载失败: {e}")
        raise

# 训练模型
def train(model, device, train_loader, optimizer, epoch, log_interval, log_file=None):
    model.train()
    for batch_idx, (data, target) in enumerate(train_loader):
        data, target = data.to(device), target.to(device)
        optimizer.zero_grad()
        output = model(data)
        loss = F.nll_loss(output, target)
        loss.backward()
        optimizer.step()
        
        if batch_idx % log_interval == 0:
            log_message = f'Train Epoch: {epoch} [{batch_idx * len(data)}/{len(train_loader.dataset)} ' \
                         f'({100. * batch_idx / len(train_loader):.0f}%)]\tLoss: {loss.item():.6f}'
            print(log_message)
            
            if log_file:
                log_file.write(log_message + '\n')

# 测试模型
def test(model, device, test_loader, log_file=None):
    model.eval()
    test_loss = 0
    correct = 0
    with torch.no_grad():
        for data, target in test_loader:
            data, target = data.to(device), target.to(device)
            output = model(data)
            test_loss += F.nll_loss(output, target, reduction='sum').item()
            pred = output.argmax(dim=1, keepdim=True)
            correct += pred.eq(target.view_as(pred)).sum().item()

    test_loss /= len(test_loader.dataset)
    accuracy = 100. * correct / len(test_loader.dataset)
    
    log_message = f'\nTest set: Average loss: {test_loss:.4f}, Accuracy: {correct}/{len(test_loader.dataset)} ' \
                 f'({accuracy:.2f}%)\n'
    print(log_message)
    
    if log_file:
        log_file.write(log_message + '\n')
    torch.cuda.empty_cache()
    return accuracy

# 主函数
def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='MNIST Poisoning Experiment')
    parser.add_argument('--data_root', type=str, default='./data', help='Path to the data directory')
    parser.add_argument('--log_file', type=str, default='./training_log.txt', help='Path to the log file')
    parser.add_argument('--batch_size', type=int, default=64, help='Input batch size for training')
    parser.add_argument('--test_batch_size', type=int, default=1000, help='Input batch size for testing')
    parser.add_argument('--epochs', type=int, default=10, help='Number of training epochs')
    parser.add_argument('--lr', type=float, default=0.01, help='Learning rate')
    parser.add_argument('--momentum', type=float, default=0.5, help='SGD momentum')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    parser.add_argument('--log_interval', type=int, default=10, help='How many batches to wait before logging training status')
    parser.add_argument('--use_cuda', action='store_true', help='Use CUDA if available')
    args = parser.parse_args()
    
    # 设置随机种子
    set_seed(args.seed)
    
    # 检查CUDA可用性
    use_cuda = args.use_cuda and torch.cuda.is_available()
    device = torch.device("cuda" if use_cuda else "cpu")
    
    # 检查日志目录是否存在，不存在则创建
    log_dir = os.path.dirname(args.log_file)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError as e:
            print(f"无法创建日志目录: {e}")
            return
    
    # 检查日志文件权限
    try:
        with open(args.log_file, 'w') as f:
            f.write(f"训练开始时间: {datetime.now()}\n")
            f.write(f"参数: {args}\n\n")
    except Exception as e:
        print(f"无法写入日志文件: {e}")
        return
    
    try:
        # 加载数据
        train_loader, test_loader = load_data(args.data_root, args.batch_size, args.test_batch_size)
        
        # 初始化模型
        model = Net().to(device)
        optimizer = optim.SGD(model.parameters(), lr=args.lr, momentum=args.momentum)
        
        # 打开日志文件
        with open(args.log_file, 'a') as log_file:
            # 训练和测试循环
            for epoch in range(1, args.epochs + 1):
                train(model, device, train_loader, optimizer, epoch, args.log_interval, log_file)
                test(model, device, test_loader, log_file)
                
                # 保存模型检查点
                checkpoint_path = os.path.join(log_dir, f'model_epoch_{epoch}.pt')
                torch.save(model.state_dict(), checkpoint_path)
                log_file.write(f"模型保存到: {checkpoint_path}\n")
        
        print(f"训练完成，日志保存在: {args.log_file}")
        
    except Exception as e:
        print(f"训练过程中发生错误: {e}")
        if 'log_file' in locals():
            with open(args.log_file, 'a') as f:
                f.write(f"错误: {e}\n")

if __name__ == '__main__':
    main()    