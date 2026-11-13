import torch


def load_checkpoint(path):
    return torch.load(path, map_location="cpu", weights_only=True)
