FROM python:3.12-slim
#cree un env virtuel pour isoler les dependances de l'appli a partir d une image de python slim ==> debian minimal

# Dépendances système nécessaires à py_landlock (chargement de libc) et pyseccomp

RUN apt-get update && apt-get install -y --no-install-recommends \
    libseccomp2 libseccomp-dev gcc gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

# torch se résolvait vers sa variante CUDA par défaut, entraînant le
# téléchargement de toute la chaîne nvidia-*/cuda- (>1,5 Go, inutile —
# aucune inférence GPU dans ce projet). Installé séparément, en premier,
# depuis l'index CPU dédié de PyTorch.
RUN TORCH_VERSION=$(grep -E "^torch==" requirements.txt | sed -E 's/^torch==//') \
    && pip install --no-cache-dir "torch==${TORCH_VERSION}" --index-url https://download.pytorch.org/whl/cpu

# Le reste de requirements.txt, sans réintroduire torch ni la chaîne CUDA
# associée (triton, nvidia-*, cuda-*) qui ne serait plus utile de toute façon.
RUN grep -vE "^(torch==|triton==|nvidia-|cuda-)" requirements.txt > /tmp/requirements-nogpu.txt \
    && pip install --no-cache-dir -r /tmp/requirements-nogpu.txt

COPY . .

# Utilisateur non privilégié — le process principal n'a jamais besoin de root
RUN useradd --create-home --shell /bin/bash runtime_user

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]