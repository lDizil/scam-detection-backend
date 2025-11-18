"""
Скрипт для дообучения модели на кастомных данных
"""

import pandas as pd
import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
)
from datasets import Dataset
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScamDataset:
    """Датасет для обучения"""

    def __init__(self, tokenizer, max_length=512):
        self.tokenizer = tokenizer
        self.max_length = max_length

    def load_data(self, csv_path: str) -> Dataset:
        """
        Загрузка данных из CSV

        Формат CSV:
        text,label
        "Срочно! Ваш аккаунт заблокирован",1
        "Привет, как дела?",0
        """
        df = pd.read_csv(csv_path)

        logger.info(f"Загружено {len(df)} примеров из {csv_path}")
        logger.info(f"Распределение классов:\n{df['label'].value_counts()}")

        # Конвертируем в HuggingFace Dataset
        dataset = Dataset.from_pandas(df)

        # Токенизируем
        dataset = dataset.map(
            self._tokenize_function, batched=True, remove_columns=dataset.column_names
        )

        return dataset

    def _tokenize_function(self, examples):
        """Токенизация текстов"""
        return self.tokenizer(
            examples["text"],
            padding="max_length",
            truncation=True,
            max_length=self.max_length,
        )


def compute_metrics(eval_pred):
    """Вычисление метрик для оценки"""
    predictions, labels = eval_pred
    predictions = predictions.argmax(axis=-1)

    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary"
    )
    accuracy = accuracy_score(labels, predictions)

    return {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}


def train_model(
    train_csv: str,
    test_csv: str,
    base_model: str = "ealvaradob/bert-finetuned-phishing",
    output_dir: str = "./training/models/custom_model",
    epochs: int = 3,
    batch_size: int = 16,
    learning_rate: float = 2e-5,
):
    """
    Дообучение модели

    Args:
        train_csv: Путь к обучающей выборке
        test_csv: Путь к тестовой выборке
        base_model: Базовая модель для дообучения
        output_dir: Директория для сохранения модели
        epochs: Количество эпох обучения
        batch_size: Размер батча
        learning_rate: Learning rate
    """
    logger.info("=" * 50)
    logger.info("НАЧАЛО ДООБУЧЕНИЯ МОДЕЛИ")
    logger.info("=" * 50)

    # Загружаем токенизатор и модель
    logger.info(f"Загрузка базовой модели: {base_model}")
    tokenizer = AutoTokenizer.from_pretrained(base_model)
    model = AutoModelForSequenceClassification.from_pretrained(base_model, num_labels=2)

    # Подготавливаем данные
    logger.info("Подготовка данных...")
    dataset_handler = ScamDataset(tokenizer)
    train_dataset = dataset_handler.load_data(train_csv)
    test_dataset = dataset_handler.load_data(test_csv)

    # Настройки обучения
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        learning_rate=learning_rate,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir=f"{output_dir}/logs",
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        save_total_limit=2,
    )

    # Создаем Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        compute_metrics=compute_metrics,
    )

    # Обучаем
    logger.info("Начинаю обучение...")
    train_result = trainer.train()

    # Оцениваем на тестовой выборке
    logger.info("Оценка на тестовой выборке...")
    eval_result = trainer.evaluate()

    # Сохраняем модель
    logger.info(f"Сохранение модели в {output_dir}")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)

    # Выводим результаты
    logger.info("=" * 50)
    logger.info("РЕЗУЛЬТАТЫ ОБУЧЕНИЯ")
    logger.info("=" * 50)
    logger.info(f"Accuracy:  {eval_result['eval_accuracy']:.4f}")
    logger.info(f"Precision: {eval_result['eval_precision']:.4f}")
    logger.info(f"Recall:    {eval_result['eval_recall']:.4f}")
    logger.info(f"F1-Score:  {eval_result['eval_f1']:.4f}")
    logger.info("=" * 50)

    logger.info(f"✅ Модель сохранена в {output_dir}")
    logger.info(f"💡 Для использования модели установите в .env:")
    logger.info(f"   CUSTOM_MODEL_PATH={output_dir}")


if __name__ == "__main__":
    # Пример использования
    train_model(
        train_csv="./training/data/train.csv",
        test_csv="./training/data/test.csv",
        output_dir="./training/models/my_finetuned_model",
        epochs=3,
        batch_size=16,
    )
