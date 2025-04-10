# 导入第三方库
import os
os.environ['KMP_DUPLICATE_LIB_OK']='True'
import torch 
import random
import torch.nn as nn 
import torch.nn.functional as F 
import numpy as np
import matplotlib.pyplot as plt
from torchvision import datasets 
from torch.utils.data import DataLoader 
from torch.utils.data import Subset 

# 定义AlexNet的结构
class AlexNet(nn.Module):
    def __init__(self):
        super(AlexNet, self).__init__()

        self.conv1 = nn.Conv2d(1, 32, kernel_size=3, padding=1)
        self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)
        self.relu1 = nn.ReLU()

        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, stride=1, padding=1)
        self.pool2 = nn.MaxPool2d(kernel_size=2, stride=2)
        self.relu2 = nn.ReLU()

        self.conv3 = nn.Conv2d(64, 128, kernel_size=3, stride=1, padding=1)
        self.conv4 = nn.Conv2d(128, 256, kernel_size=3, stride=1, padding=1)
        self.conv5 = nn.Conv2d(256, 256, kernel_size=3, stride=1, padding=1)
        self.pool3 = nn.MaxPool2d(kernel_size=2, stride=2)
        self.relu3 = nn.ReLU()

        self.fc6 = nn.Linear(256 * 3 * 3, 1024)
        self.fc7 = nn.Linear(1024, 512)
        self.fc8 = nn.Linear(512, 10)

    def forward(self, x):
        x = self.conv1(x)
        x = self.pool1(x)
        x = self.relu1(x)
        x = self.conv2(x)
        x = self.pool2(x)
        x = self.relu2(x)
        x = self.conv3(x)
        x = self.conv4(x)
        x = self.conv5(x)
        x = self.pool3(x)
        x = self.relu3(x)
        x = x.view(-1, 256 * 3 * 3)
        x = self.fc6(x)
        x = F.relu(x)
        x = self.fc7(x)
        x = F.relu(x)
        x = self.fc8(x)
        return x

#划分数据集，使用原数据集的1/10
def select_subset(dataset, ratio=1/10):
    subset_size = int(len(dataset) * ratio)
    indices = np.random.choice(range(len(dataset)), subset_size, replace=False)
    return Subset(dataset, indices)

# 展示正确分类的图片
def plot_correctly_classified_images(model, dataset, device, num_images=10):
    model.eval()
    correctly_classified_imgs = []

    for img, label in dataset:
        img = img.type(torch.FloatTensor).unsqueeze(0).unsqueeze(0).to(device)
        with torch.no_grad():
            pred = model(img)
        pred_label = torch.argmax(pred).item()

        if pred_label == label:
            correctly_classified_imgs.append((img.cpu().squeeze(), label, pred_label))
            if len(correctly_classified_imgs) >= num_images:
                break

    plt.figure(figsize=(10, 10))
    for i, (img, true_label, pred_label) in enumerate(correctly_classified_imgs):
        plt.subplot(5, 2, i + 1)
        plt.imshow(img.numpy(), cmap='gray')
        plt.title(f"True: {true_label}, Pred: {pred_label}")
        plt.axis('off')
    plt.tight_layout()
    plt.show()
# 展示错误分类的图片
def plot_misclassified_images(model, dataset, device, num_images=10):
    model.eval()
    misclassified_imgs = []

    for img, label in dataset:
        img = img.type(torch.FloatTensor).unsqueeze(0).unsqueeze(0).to(device)
        with torch.no_grad():
            pred = model(img)
        pred_label = torch.argmax(pred).item()

        if pred_label != label:
            misclassified_imgs.append((img.cpu().squeeze(), label, pred_label))
            if len(misclassified_imgs) >= num_images:
                break

    plt.figure(figsize=(10, 10))
    for i, (img, true_label, pred_label) in enumerate(misclassified_imgs):
        plt.subplot(5, 2, i + 1)
        plt.imshow(img.numpy(), cmap='gray')
        plt.title(f"True: {true_label}, Pred: {pred_label}")
        plt.axis('off')
    plt.tight_layout()
    plt.show()

# 对训练数据集进行切分，ratio用于控制干净样本与投毒样本比例
def fetch_datasets(full_dataset, trainset, ratio):
    character = [[] for i in range(len(full_dataset.classes))]
    for index in trainset.indices:
        img, label = full_dataset[index]
        character[label].append(img)

    poison_trainset = []
    clean_trainset = []
    target = 0
    for i, data in enumerate(character):
        num_poison_train_inputs = int(len(data) * ratio[0])
        for img in data[:num_poison_train_inputs]:
            #target = (i + 1) % 10
            target = random.randint(0, 9)
            poison_img = img
            poison_img = torch.from_numpy(np.array(poison_img) / 255.0)
            poison_trainset.append((poison_img, target))
        for img in data[num_poison_train_inputs:]:
            # 干净数据集标签不变
            img = np.array(img)
            img = torch.from_numpy(img/255.0)
            clean_trainset.append((img, i))

    result_datasets = {}
    result_datasets['poisonTrain'] = poison_trainset
    result_datasets['cleanTrain'] = clean_trainset
    return result_datasets

#投毒比例
clean_rate = 0.5
poison_rate = 0.5

#从库中获取训练集
trainset_all = datasets.MNIST(root="../data", download=True, train=True)
trainset = select_subset(trainset_all)
all_datasets = fetch_datasets(full_dataset=trainset_all, trainset=trainset, ratio=[poison_rate, clean_rate])
poison_trainset = all_datasets['poisonTrain']
clean_trainset = all_datasets['cleanTrain']
all_trainset = poison_trainset.__add__(clean_trainset)

#从库中获取测试集
clean_test_all = datasets.MNIST(root='../data', download=True, train=False)
clean_test = select_subset(clean_test_all)
clean_testset = []
for img, label in clean_test:
    img = np.array(img)
    img = torch.from_numpy(img/255.0)
    clean_testset.append((img, label))

#数据加载器
trainset_dataloader = DataLoader(dataset=all_trainset, batch_size=64, shuffle=True)

print("开始对模型投毒.......................")
device = torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")
net = AlexNet().to(device)

loss_fn = torch.nn.CrossEntropyLoss().to(device)
optimizer = torch.optim.Adam(net.parameters(), lr=0.001)#lr=0.005

clean_acc_list = []
epoch = 20
clean_correct = 0
loss_list = []
file = open("training_log.txt", "w")

for epoch in range(epoch):
    running_loss = 0.0

    for index, (imgs, labels) in enumerate(trainset_dataloader, 0):
        imgs = imgs.unsqueeze(1)
        imgs = imgs.type(torch.FloatTensor)
        imgs, labels = imgs.to(device), labels.to(device)
        optimizer.zero_grad()
        outputs = net(imgs)
        loss = loss_fn(outputs, labels)
        loss.backward()
        optimizer.step()
        running_loss += loss.item()

    print("Epoch: {}, loss: {}".format(epoch + 1, running_loss))
    file.write("Epoch: " + str(epoch + 1) + ", loss: " + str(running_loss) + "\n")
    loss_list.append(running_loss)
    file.flush()

    # 在循环体外部测试样本准确率
    print("测试每一轮干净样本准确率: Epoch " + str(epoch + 1) + " ------------------")
    clean_correct = 0
    for img, label in clean_testset:
        img = img.type(torch.FloatTensor)
        img = img.unsqueeze(0).unsqueeze(0).to(device)
        pred = net(img)
        pred = torch.reshape(pred, (10,))
        top_pred = torch.argmax(pred)
        if top_pred.item() == label:
            clean_correct += 1
    clean_acc = clean_correct / len(clean_testset) * 100
    clean_acc_list.append(clean_acc)
    print("干净样本准确率为: " + str(clean_acc) + '%\n')

    #plot_misclassified_images(net, clean_testset, device)
    #plot_correctly_classified_images(net, clean_testset, device, num_images=10)
file.close()
plot_misclassified_images(net, clean_testset, device)
plot_correctly_classified_images(net, clean_testset, device, num_images=10)

# 绘制线型图
plt.rcParams['font.size'] = 16
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False
plt.figure(figsize=(10, 6))
plt.plot(range(1, len(clean_acc_list) + 1),
         clean_acc_list, label='Accuracy', marker='o', linestyle='-')
plt.title(f'投毒比例={poison_rate}')
plt.xlabel('训练轮数(epoch)')
plt.ylabel('准确率 (%)')
plt.ylim(0, 100)
plt.legend()
plt.grid(True)
plt.show()

plt.rcParams['font.size'] = 16
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False
plt.figure(figsize=(10, 6))
plt.plot(range(1, len(loss_list) + 1),
         loss_list, label='Loss', marker='o', linestyle='-')
plt.title(f'投毒比例={poison_rate}')
plt.xlabel('训练轮数(epoch)')
plt.ylabel('损失值')
plt.ylim(0, max(loss_list) * 1.1)
plt.legend()
plt.grid(True)
plt.show()

