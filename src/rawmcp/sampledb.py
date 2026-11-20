"""Deterministic generator for the bundled sample database (synthetic retail orders).

The committed ``rawmcp/data/sample.db`` is produced by ``python scripts/build_sample_db.py``;
a test rebuilds it in a temporary directory and checks the two are identical, so the binary
file in the repository is always reproducible from this code. All names and figures are
synthetic.
"""

from __future__ import annotations

import hashlib
import random
import sqlite3
from datetime import date, timedelta
from pathlib import Path

SCHEMA = """
CREATE TABLE customers (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    country     TEXT NOT NULL,
    segment     TEXT NOT NULL CHECK (segment IN ('retail', 'smb', 'enterprise')),
    signup_date TEXT NOT NULL
);
CREATE TABLE products (
    id         INTEGER PRIMARY KEY,
    sku        TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    category   TEXT NOT NULL,
    unit_price REAL NOT NULL CHECK (unit_price > 0)
);
CREATE TABLE orders (
    id          INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    order_date  TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('placed', 'shipped', 'delivered', 'returned', 'cancelled')),
    channel     TEXT NOT NULL CHECK (channel IN ('web', 'store', 'partner'))
);
CREATE TABLE order_items (
    order_id   INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    quantity   INTEGER NOT NULL CHECK (quantity > 0),
    unit_price REAL NOT NULL,
    PRIMARY KEY (order_id, product_id)
);
CREATE INDEX idx_orders_customer ON orders(customer_id);
CREATE INDEX idx_items_product ON order_items(product_id);
""".strip()

_PREFIXES = ["Alpine", "Borealis", "Cobalt", "Delta", "Ember", "Fjord", "Granite", "Harbor", "Iris", "Juniper",
             "Kestrel", "Lumen", "Meridian", "Nimbus", "Orchid", "Pioneer", "Quartz", "Riviera", "Summit", "Tidal"]
_SUFFIXES = ["Labs", "Studio", "Supply", "Works", "Trading", "Group", "Collective", "Partners", "Goods"]
_COUNTRIES = ["Italy", "Germany", "France", "Spain", "Netherlands", "Austria", "Portugal", "Belgium"]
_CATALOGUE = {
    "office": ["Desk lamp", "Notebook A5", "Fountain pen", "Monitor stand", "Cable tray", "Whiteboard"],
    "kitchen": ["Pour-over kettle", "Ceramic mug", "Chef knife", "Cutting board", "Spice rack", "French press"],
    "outdoor": ["Trail backpack", "Water bottle", "Headlamp", "Camping stove", "Rain shell", "Trekking poles"],
    "electronics": ["USB-C hub", "Wireless mouse", "Mechanical keyboard", "Noise-cancelling headset",
                    "Portable SSD", "Webcam"],
}


def build_sample_db(path: Path, seed: int = 2026) -> None:
    """Create the sample database at ``path`` (overwriting it)."""
    if path.exists():
        path.unlink()
    rng = random.Random(seed)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        start = date(2024, 1, 1)
        customers = []
        for cid in range(1, 61):
            name = f"{rng.choice(_PREFIXES)} {rng.choice(_SUFFIXES)} {cid:02d}"
            segment = rng.choices(["retail", "smb", "enterprise"], weights=[5, 3, 1])[0]
            signup = start + timedelta(days=rng.randrange(0, 365))
            customers.append((cid, name, rng.choice(_COUNTRIES), segment, signup.isoformat()))
        conn.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?)", customers)

        products = []
        pid = 0
        for category, names in _CATALOGUE.items():
            for name in names:
                pid += 1
                price = round(rng.uniform(4, 180), 2)
                products.append((pid, f"{category[:3].upper()}-{pid:03d}", name, category, price))
        conn.executemany("INSERT INTO products VALUES (?, ?, ?, ?, ?)", products)

        statuses = ["placed", "shipped", "delivered", "returned", "cancelled"]
        orders, items = [], []
        for oid in range(1, 501):
            customer = rng.choice(customers)
            day = date.fromisoformat(customer[4]) + timedelta(days=rng.randrange(0, 400))
            status = rng.choices(statuses, weights=[1, 2, 12, 1, 1])[0]
            orders.append((oid, customer[0], day.isoformat(), status, rng.choice(["web", "web", "store", "partner"])))
            for product in rng.sample(products, k=rng.randint(1, 4)):
                items.append((oid, product[0], rng.randint(1, 5), product[4]))
        conn.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?)", orders)
        conn.executemany("INSERT INTO order_items VALUES (?, ?, ?, ?)", items)
        conn.commit()
        conn.execute("VACUUM")
    finally:
        conn.close()


def content_digest(path: Path) -> str:
    """SHA-256 over the SQL dump, so two databases with equal content compare equal."""
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        digest = hashlib.sha256()
        for line in conn.iterdump():
            digest.update(line.encode("utf-8"))
        return digest.hexdigest()
    finally:
        conn.close()
