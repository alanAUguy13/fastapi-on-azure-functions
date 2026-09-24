# Azure Functions (Python v2 model) container for the ShelfCat Truth API.
FROM mcr.microsoft.com/azure-functions/python:4-python3.11

ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt /
RUN pip install -r /requirements.txt

COPY host.json function_app.py /home/site/wwwroot/
COPY WrapperFunction /home/site/wwwroot/WrapperFunction
