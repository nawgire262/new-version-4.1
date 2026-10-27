import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

BASE_DIR = Path(r"C:\Users\OM\Downloads\SentinelShield-WiFi-Threat-Detection-Latest\SentinelShield-WiFi-Threat-Detection")
OUTPUT_DIR = BASE_DIR / "research_evaluation_output"

cms = [
    ("Random Forest", 9, 0, 142, 0),
    ("KNN Classifier", 9, 0, 142, 0),
    ("Isolation Forest", 9, 8, 134, 0),
    ("RF + KNN Ensemble", 9, 0, 142, 0),
    ("SentinelShield Hybrid Stack", 9, 0, 142, 0)
]

fig, axes = plt.subplots(1, 5, figsize=(16, 3.8), dpi=300)

for ax, (title, tp, fp, tn, fn) in zip(axes, cms):
    cm = np.array([[tn, fp], [fn, tp]])
    im = ax.imshow(cm, cmap="Blues", interpolation="nearest")
    ax.set_title(title, fontsize=10.5, fontweight="bold", pad=8)
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Pred Legit", "Pred Fake"], fontsize=8.5)
    ax.set_yticklabels(["True Legit", "True Fake"], fontsize=8.5)
    
    for i in range(2):
        for j in range(2):
            val = cm[i, j]
            color = "white" if val > 70 else "black"
            ax.text(j, i, str(val), ha="center", va="center", color=color, fontweight="bold", fontsize=11)

plt.suptitle("Figure 8.4.4: Confusion Matrices across Evaluated Models (training_dataset.csv)", 
             fontsize=12, fontweight="bold", y=1.03)
plt.tight_layout()
out_file = OUTPUT_DIR / "Figure_8_4_4_Confusion_Matrices.png"
plt.savefig(out_file, bbox_inches="tight")
plt.close()
print("Saved:", out_file)

