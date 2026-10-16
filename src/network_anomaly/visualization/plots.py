"""Visualization helpers."""
import matplotlib.pyplot as plt


def save_confusion_matrix(cm, title="Confusion Matrix"):
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.imshow(cm, cmap="Blues")
    ax.set_title(title)
    plt.tight_layout()
    return fig
