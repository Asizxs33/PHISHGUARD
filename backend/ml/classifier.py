"""
PhishGuard AI — Deep Learning Phishing Classifier
Deep Neural Network with Residual Blocks and Feature Attention.
"""

import os
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from typing import Dict, Any, Tuple, List

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')


# ─── Neural Network Components ──────────────────────────────────────────


class FeatureAttention(nn.Module):
    """Learnable attention gate over input features.
    Learns which features are most important for classification."""

    def __init__(self, dim):
        super().__init__()
        self.gate = nn.Sequential(
            nn.Linear(dim, dim * 2),
            nn.GELU(),
            nn.Linear(dim * 2, dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        weights = self.gate(x)
        return x * weights, weights


class ResidualBlock(nn.Module):
    """Residual block with skip connection, BatchNorm, and GELU activation."""

    def __init__(self, dim, dropout=0.3):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
        )
        self.activation = nn.GELU()
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        residual = x
        out = self.block(x)
        out = self.dropout(self.activation(out + residual))
        return out


class PhishingNet(nn.Module):
    """
    Deep Neural Network for phishing detection.

    Architecture:
      1. Feature Attention — learns to weight input features
      2. Input Projection — projects features to hidden dimension
      3. 3x Residual Blocks — deep feature extraction with skip connections
      4. Dimension Reduction — compresses representation
      5. Classification Head — outputs phishing probability [0,1]
    """

    def __init__(self, input_dim, hidden_dim=256, num_res_blocks=3, dropout=0.3):
        super().__init__()
        self.input_dim = input_dim

        # Feature attention gate
        self.feature_attention = FeatureAttention(input_dim)

        # Input projection
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        # Stack of residual blocks
        self.res_blocks = nn.ModuleList([
            ResidualBlock(hidden_dim, dropout) for _ in range(num_res_blocks)
        ])

        # Dimension reduction path
        self.reduction = nn.Sequential(
            nn.Linear(hidden_dim, 128),
            nn.BatchNorm1d(128),
            nn.GELU(),
            nn.Dropout(dropout * 0.7),

            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Dropout(dropout * 0.5),
        )

        # Classification head
        self.head = nn.Sequential(
            nn.Linear(64, 32),
            nn.GELU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        # Apply feature attention
        x, attn_weights = self.feature_attention(x)

        # Project to hidden dimension
        x = self.input_proj(x)

        # Pass through residual blocks
        for block in self.res_blocks:
            x = block(x)

        # Reduce dimensions
        x = self.reduction(x)

        # Classify
        out = self.head(x)
        return out, attn_weights


# ─── Classifier Wrapper ─────────────────────────────────────────────────


class PhishingClassifier:
    """
    Deep Learning phishing classifier.

    Wraps PyTorch PhishingNet with train/predict/save/load interface.
    Uses StandardScaler for feature normalization and attention weights
    for feature importance interpretation.
    """

    def __init__(self):
        self.model: PhishingNet = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names: List[str] = []
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.training_history: Dict[str, list] = {}

    def train(self, X: np.ndarray, y: np.ndarray,
              feature_names: List[str] = None,
              epochs: int = 150, batch_size: int = 64, lr: float = 0.001) -> Dict[str, Any]:
        """
        Train the deep learning model.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels (n_samples,) — 0=safe, 1=phishing
            feature_names: Optional list of feature names
            epochs: Maximum training epochs
            batch_size: Batch size for training
            lr: Initial learning rate

        Returns:
            Dictionary with training metrics
        """
        if feature_names:
            self.feature_names = feature_names

        # ── Normalize features ──
        X_scaled = self.scaler.fit_transform(X)

        # ── Train/Validation split ──
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y, test_size=0.15, random_state=42, stratify=y
        )

        # ── Create DataLoaders ──
        train_dataset = TensorDataset(
            torch.FloatTensor(X_train),
            torch.FloatTensor(y_train).unsqueeze(1)
        )
        val_dataset = TensorDataset(
            torch.FloatTensor(X_val),
            torch.FloatTensor(y_val).unsqueeze(1)
        )
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, drop_last=False)
        val_loader = DataLoader(val_dataset, batch_size=batch_size)

        # ── Initialize model ──
        input_dim = X.shape[1]
        self.model = PhishingNet(input_dim).to(self.device)

        total_params = sum(p.numel() for p in self.model.parameters())
        trainable_params = sum(p.numel() for p in self.model.parameters() if p.requires_grad)
        print(f"\n   🧠 Network: PhishingNet (Residual + Attention)")
        print(f"   📐 Parameters: {total_params:,} total ({trainable_params:,} trainable)")
        print(f"   🖥️  Device: {self.device}")
        print(f"   📊 Data: {len(X_train)} train / {len(X_val)} validation samples")
        print()

        # ── Loss, Optimizer, Scheduler ──
        criterion = nn.BCELoss()
        optimizer = optim.AdamW(self.model.parameters(), lr=lr, weight_decay=1e-4)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode='min', patience=15, factor=0.5, min_lr=1e-6
        )

        # ── Training loop with early stopping ──
        best_val_loss = float('inf')
        best_val_acc = 0.0
        patience_counter = 0
        patience = 25
        best_state = None

        history = {'train_loss': [], 'val_loss': [], 'val_acc': []}

        for epoch in range(epochs):
            # ── Train phase ──
            self.model.train()
            train_loss = 0.0
            train_correct = 0
            train_total = 0

            for X_batch, y_batch in train_loader:
                X_batch = X_batch.to(self.device)
                y_batch = y_batch.to(self.device)

                optimizer.zero_grad()
                output, _ = self.model(X_batch)
                loss = criterion(output, y_batch)
                loss.backward()

                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

                optimizer.step()

                train_loss += loss.item() * X_batch.size(0)
                predicted = (output >= 0.5).float()
                train_correct += (predicted == y_batch).sum().item()
                train_total += y_batch.size(0)

            train_loss /= train_total
            train_acc = train_correct / train_total

            # ── Validation phase ──
            self.model.eval()
            val_loss = 0.0
            val_correct = 0
            val_total = 0

            with torch.no_grad():
                for X_batch, y_batch in val_loader:
                    X_batch = X_batch.to(self.device)
                    y_batch = y_batch.to(self.device)

                    output, _ = self.model(X_batch)
                    loss = criterion(output, y_batch)

                    val_loss += loss.item() * X_batch.size(0)
                    predicted = (output >= 0.5).float()
                    val_correct += (predicted == y_batch).sum().item()
                    val_total += y_batch.size(0)

            val_loss /= val_total
            val_acc = val_correct / val_total

            history['train_loss'].append(train_loss)
            history['val_loss'].append(val_loss)
            history['val_acc'].append(val_acc)

            scheduler.step(val_loss)
            current_lr = optimizer.param_groups[0]['lr']

            # Print progress every 10 epochs
            if (epoch + 1) % 10 == 0 or epoch == 0:
                print(f"   Epoch {epoch+1:3d}/{epochs} │ "
                      f"Train Loss: {train_loss:.4f} Acc: {train_acc:.4f} │ "
                      f"Val Loss: {val_loss:.4f} Acc: {val_acc:.4f} │ "
                      f"LR: {current_lr:.6f}")

            # ── Early stopping ──
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_val_acc = val_acc
                best_state = {k: v.clone() for k, v in self.model.state_dict().items()}
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print(f"\n   ⏹️  Early stopping at epoch {epoch+1} (no improvement for {patience} epochs)")
                    break

        # ── Restore best model ──
        if best_state is not None:
            self.model.load_state_dict(best_state)

        self.is_trained = True
        self.training_history = history

        metrics = {
            'architecture': 'PhishingNet (Residual + Attention)',
            'total_parameters': total_params,
            'trainable_parameters': trainable_params,
            'input_features': input_dim,
            'epochs_trained': len(history['train_loss']),
            'best_val_accuracy': round(best_val_acc, 4),
            'best_val_loss': round(best_val_loss, 4),
            'final_train_loss': round(history['train_loss'][-1], 4),
            'device': str(self.device),
        }

        return metrics

    def predict(self, features: np.ndarray) -> Tuple[float, str, Dict[str, Any]]:
        """
        Predict phishing probability using the deep learning model.

        Args:
            features: Feature vector (n_features,) or (1, n_features)

        Returns:
            score: float 0.0 (safe) to 1.0 (phishing)
            verdict: str "safe", "suspicious", or "phishing"
            details: dict with model info and feature importance
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() or load() first.")

        if features.ndim == 1:
            features = features.reshape(1, -1)

        # Normalize features
        features_scaled = self.scaler.transform(features)
        X_tensor = torch.FloatTensor(features_scaled).to(self.device)

        # Predict
        self.model.eval()
        with torch.no_grad():
            output, attn_weights = self.model(X_tensor)

        score = round(float(output.squeeze().item()), 4)
        attn = attn_weights.squeeze().cpu().numpy()

        # Determine verdict
        if score < 0.3:
            verdict = "safe"
        elif score < 0.7:
            verdict = "suspicious"
        else:
            verdict = "phishing"

        # Feature importance from attention weights
        importances = {}
        if self.feature_names and len(self.feature_names) == len(attn):
            attn_normalized = attn / (attn.sum() + 1e-8)
            sorted_idx = np.argsort(attn_normalized)[::-1]
            for i in sorted_idx[:5]:
                if i < len(self.feature_names):
                    importances[self.feature_names[i]] = round(float(attn_normalized[i]), 4)

        # Confidence: how far from 0.5 (uncertain) the prediction is
        confidence = round(abs(score - 0.5) * 2, 4)  # 0 = uncertain, 1 = very confident

        details = {
            'neural_network_score': score,
            'confidence': confidence,
            'top_features': importances,
            'model_type': 'Deep Neural Network (Residual + Attention)',
        }

        return score, verdict, details

    def save(self, name: str = 'phishing_model') -> str:
        """Save model, scaler, and metadata to disk."""
        os.makedirs(MODELS_DIR, exist_ok=True)
        path = os.path.join(MODELS_DIR, f'{name}.pth')

        data = {
            'model_state': self.model.state_dict(),
            'model_config': {
                'input_dim': self.model.input_dim,
            },
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
        }
        torch.save(data, path)
        print(f"✅ Model saved to {path}")
        return path

    def load(self, name: str = 'phishing_model') -> bool:
        """Load model, scaler, and metadata from disk."""
        path = os.path.join(MODELS_DIR, f'{name}.pth')
        if not os.path.exists(path):
            print(f"⚠️ Model file not found: {path}")
            return False

        try:
            data = torch.load(path, map_location=self.device, weights_only=False)

            config = data['model_config']
            self.model = PhishingNet(config['input_dim']).to(self.device)
            self.model.load_state_dict(data['model_state'])
            self.model.eval()

            self.scaler = data['scaler']
            self.feature_names = data['feature_names']
            self.is_trained = data['is_trained']

            total_params = sum(p.numel() for p in self.model.parameters())
            print(f"✅ Deep Learning model loaded from {path} ({total_params:,} params)")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False
