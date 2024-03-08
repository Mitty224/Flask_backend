def drop_posts_db(conn):
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS posts;")
def init_posts_db(conn):
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS posts;")

    cur.execute('''
        CREATE TABLE posts (
        id SERIAL PRIMARY KEY,
        content TEXT, 
        author TEXT, 
        tags TEXT, 
        createdAt TIMESTAMP NOT NULL,
        likesCount INTEGER NOT NULL DEFAULT 0, 
        dislikesCount INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (author) REFERENCES bd_users (login)
        );
    ''')

    conn.commit()