from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import os

app = FastAPI()

# Configurar CORS para permitir peticiones desde el frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelo de datos
class Todo(BaseModel):
    title: str
    completed: bool = False

# Conexión a la base de datos
def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST", "db"),
        database=os.getenv("DB_NAME", "tododb"),
        user=os.getenv("DB_USER", "todouser"),
        password=os.getenv("DB_PASSWORD", "todopass")
    )
    return conn

# Inicializar tabla
@app.on_event("startup")
async def startup():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            completed BOOLEAN DEFAULT FALSE
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

# Endpoints
@app.get("/")
async def root():
    return {"message": "TODO API is running"}

@app.get("/todos")
async def get_todos():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM todos ORDER BY id")
    todos = cur.fetchall()
    cur.close()
    conn.close()
    return todos

@app.post("/todos")
async def create_todo(todo: Todo):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "INSERT INTO todos (title, completed) VALUES (%s, %s) RETURNING *",
        (todo.title, todo.completed)
    )
    new_todo = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return new_todo

@app.put("/todos/{todo_id}")
async def update_todo(todo_id: int):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "UPDATE todos SET completed = NOT completed WHERE id = %s RETURNING *",
        (todo_id,)
    )
    updated_todo = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not updated_todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    return updated_todo

@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM todos WHERE id = %s", (todo_id,))
    deleted = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"message": "Todo deleted"}