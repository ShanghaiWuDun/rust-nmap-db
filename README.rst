rust-nmap-db
================


.. contents:: 



Build
---------

.. code:: bash
    
    python3 scripts/mkdb.py > src/db.rs

    cargo build
    cargo test

    cargo run --example service_detect 127.0.0.1:22
    cargo run --example service_detect 127.0.0.1:80
    cargo run --example service_detect 127.0.0.1:6379

