from fastapi import  APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from utils.log_config import setup_logging

logger = setup_logging(__name__)

router = APIRouter()

templates = Jinja2Templates(directory="app/dashboard/templates")

@router.get("/")
def get_index(request: Request):
    return templates.TemplateResponse(name="index.html", context={"request": request})