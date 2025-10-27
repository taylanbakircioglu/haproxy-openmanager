import logging
import json
import os
import secrets
from datetime import datetime, timedelta
from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)

async def run_init_sql():
    """Run the initial database setup from init.sql"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if basic tables already exist
        tables_exist = await conn.fetchval("""
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_name IN ('haproxy_clusters', 'users', 'config_versions')
        """)
        
        # init.sql is deprecated - all schema creation handled by migration system
        logger.info("init.sql is deprecated - using migration system for all schema creation")
        return
        
    except Exception as e:
        logger.error(f"Error running init.sql: {e}")
        raise
    finally:
        if conn:
            await close_database_connection(conn)

async def ensure_agents_table():
    """Ensures that all necessary tables, columns, and types exist in the database."""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Ensure config_status enum type exists
        enum_exists = await conn.fetchval("""
            SELECT 1 FROM pg_type WHERE typname = 'config_status'
        """)
        if not enum_exists:
            logger.info("Creating config_status enum type...")
            await conn.execute("CREATE TYPE config_status AS ENUM ('PENDING', 'APPLIED');")
            logger.info("Successfully created config_status enum type.")

        # First, create essential tables if they don't exist
        await create_essential_tables(conn)
        
        # Ensure status column exists in config_versions table
        status_column_exists = await conn.fetchval("""
            SELECT 1 FROM information_schema.columns 
            WHERE table_name='config_versions' AND column_name='status'
        """)
        if not status_column_exists:
            logger.info("Adding status column to config_versions table...")
            await conn.execute("ALTER TABLE config_versions ADD COLUMN status config_status DEFAULT 'APPLIED';")
            logger.info("Successfully added status column to config_versions.")

        # Update existing NULL status values to 'APPLIED'
        await conn.execute("UPDATE config_versions SET status = 'APPLIED' WHERE status IS NULL;")
        logger.info("Updated existing NULL status values to 'APPLIED'.")

        # Ensure waf_rules.config JSONB column exists (for consolidated WAF rule configs)
        waf_config_exists = await conn.fetchval("""
            SELECT 1 FROM information_schema.columns 
            WHERE table_name='waf_rules' AND column_name='config'
        """)
        if not waf_config_exists:
            logger.info("Adding config JSONB column to waf_rules table...")
            await conn.execute("ALTER TABLE waf_rules ADD COLUMN config JSONB NOT NULL DEFAULT '{}'::jsonb;")
            logger.info("Successfully added waf_rules.config column.")
        
        # Add cluster_id column to waf_rules for cluster-specific WAF rules
        waf_cluster_id_exists = await conn.fetchval("""
            SELECT 1 FROM information_schema.columns 
            WHERE table_name='waf_rules' AND column_name='cluster_id'
        """)
        if not waf_cluster_id_exists:
            logger.info("Adding cluster_id column to waf_rules table...")
            await conn.execute("ALTER TABLE waf_rules ADD COLUMN cluster_id INTEGER REFERENCES haproxy_clusters(id) ON DELETE CASCADE;")
            logger.info("Successfully added cluster_id column to waf_rules table.")
            
            # Update unique constraint to be cluster-specific
            try:
                # Drop existing unique constraint on name
                await conn.execute("ALTER TABLE waf_rules DROP CONSTRAINT IF EXISTS waf_rules_name_key;")
                # Add new unique constraint on (name, cluster_id)
                await conn.execute("ALTER TABLE waf_rules ADD CONSTRAINT waf_rules_name_cluster_unique UNIQUE (name, cluster_id);")
                logger.info("Updated waf_rules unique constraint to be cluster-specific (name, cluster_id).")
            except Exception as constraint_error:
                logger.warning(f"Could not update waf_rules unique constraint: {constraint_error}")

        # Ensure haproxy_user and haproxy_group columns in haproxy_clusters
        columns_to_add = {
            'haproxy_user': "ALTER TABLE haproxy_clusters ADD COLUMN haproxy_user VARCHAR(255) DEFAULT 'haproxy';",
            'haproxy_group': "ALTER TABLE haproxy_clusters ADD COLUMN haproxy_group VARCHAR(255) DEFAULT 'haproxy';"
        }
        
        for col, query in columns_to_add.items():
            column_exists = await conn.fetchval(f"""
                SELECT 1 FROM information_schema.columns 
                WHERE table_name='haproxy_clusters' AND column_name='{col}'
            """)
            if not column_exists:
                logger.info(f"Column '{col}' not found in 'haproxy_clusters', adding it...")
                await conn.execute(query)
                logger.info(f"Successfully added column '{col}' to 'haproxy_clusters'.")

        # Ensure frontend columns exist (for comprehensive frontend config support)
        frontend_columns = {
            'ssl_cert': "ALTER TABLE frontends ADD COLUMN ssl_cert TEXT;",
            'ssl_verify': "ALTER TABLE frontends ADD COLUMN ssl_verify VARCHAR(50) DEFAULT 'optional';",
            'timeout_client': "ALTER TABLE frontends ADD COLUMN timeout_client INTEGER;",
            'timeout_http_request': "ALTER TABLE frontends ADD COLUMN timeout_http_request INTEGER;",
            'rate_limit': "ALTER TABLE frontends ADD COLUMN rate_limit INTEGER;",
            'compression': "ALTER TABLE frontends ADD COLUMN compression BOOLEAN DEFAULT FALSE;",
            'log_separate': "ALTER TABLE frontends ADD COLUMN log_separate BOOLEAN DEFAULT FALSE;",
            'monitor_uri': "ALTER TABLE frontends ADD COLUMN monitor_uri VARCHAR(255);",
            'use_backend_rules': "ALTER TABLE frontends ADD COLUMN use_backend_rules TEXT;",
            'request_headers': "ALTER TABLE frontends ADD COLUMN request_headers TEXT;",
            'response_headers': "ALTER TABLE frontends ADD COLUMN response_headers TEXT;",
            'maxconn': "ALTER TABLE frontends ADD COLUMN maxconn INTEGER;"
        }
        
        for col, query in frontend_columns.items():
            column_exists = await conn.fetchval(f"""
                SELECT 1 FROM information_schema.columns 
                WHERE table_name='frontends' AND column_name='{col}'
            """)
            if not column_exists:
                logger.info(f"Column '{col}' not found in 'frontends', adding it...")
                await conn.execute(query)
                logger.info(f"Successfully added column '{col}' to 'frontends'.")

        # Entity config status enum and per-entity status columns
        entity_status_enum_exists = await conn.fetchval("""
            SELECT 1 FROM pg_type WHERE typname = 'config_entity_status'
        """)
        if not entity_status_enum_exists:
            logger.info("Creating config_entity_status enum type...")
            await conn.execute("CREATE TYPE config_entity_status AS ENUM ('PENDING','APPLIED','REJECTED');")
            logger.info("Successfully created config_entity_status enum type.")

        # Add last_config_status to entities if missing
        entity_tables = ['waf_rules', 'frontends', 'backends', 'ssl_certificates']
        for table in entity_tables:
            col_exists = await conn.fetchval(f"""
                SELECT 1 FROM information_schema.columns 
                WHERE table_name='{table}' AND column_name='last_config_status'
            """)
            if not col_exists:
                logger.info(f"Adding last_config_status to {table}...")
                await conn.execute(f"ALTER TABLE {table} ADD COLUMN last_config_status config_entity_status DEFAULT 'APPLIED';")
                logger.info(f"Added last_config_status to {table}.")

        # Add missing columns to existing tables
        missing_columns = {
            'backends': {
                'backend_id': "ALTER TABLE backends ADD COLUMN backend_id VARCHAR(255);",
                'cluster_id': "ALTER TABLE backends ADD COLUMN cluster_id INTEGER;"
            },
            'users': {
                'role': "ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'user';",
                'last_login_at': "ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP;"
            },
            'ssl_certificates': {
                'expires_at': "ALTER TABLE ssl_certificates ADD COLUMN expires_at TIMESTAMP;",
                'auto_renew': "ALTER TABLE ssl_certificates ADD COLUMN auto_renew BOOLEAN DEFAULT FALSE;",
                'cluster_id': "ALTER TABLE ssl_certificates ADD COLUMN cluster_id INTEGER;"
            },
            'agents': {
                'architecture': "ALTER TABLE agents ADD COLUMN architecture VARCHAR(50) DEFAULT 'amd64';",
                'version': "ALTER TABLE agents ADD COLUMN version VARCHAR(50) DEFAULT '1.0.0';",
                'enabled': "ALTER TABLE agents ADD COLUMN enabled BOOLEAN DEFAULT TRUE;",
                'haproxy_status': "ALTER TABLE agents ADD COLUMN haproxy_status VARCHAR(50) DEFAULT 'unknown';",
                'haproxy_version': "ALTER TABLE agents ADD COLUMN haproxy_version VARCHAR(50);",
                'config_version': "ALTER TABLE agents ADD COLUMN config_version VARCHAR(100);",
                'applied_config_version': "ALTER TABLE agents ADD COLUMN applied_config_version VARCHAR(100);",
                'last_validation_error': "ALTER TABLE agents ADD COLUMN last_validation_error TEXT;",
                'last_validation_error_at': "ALTER TABLE agents ADD COLUMN last_validation_error_at TIMESTAMP;"
            },
            'haproxy_cluster_pools': {
                'location': "ALTER TABLE haproxy_cluster_pools ADD COLUMN location VARCHAR(255);",
                'is_active': "ALTER TABLE haproxy_cluster_pools ADD COLUMN is_active BOOLEAN DEFAULT TRUE;"
            },
            'haproxy_clusters': {
                'pool_id': "ALTER TABLE haproxy_clusters ADD COLUMN pool_id INTEGER;",
                'haproxy_config_path': "ALTER TABLE haproxy_clusters ADD COLUMN haproxy_config_path VARCHAR(500) DEFAULT '/etc/haproxy/haproxy.cfg';"
            },
            'user_activity_logs': {
                'created_at': "ALTER TABLE user_activity_logs ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;"
            },
            'config_versions': {
                'cluster_id': "ALTER TABLE config_versions ADD COLUMN cluster_id INTEGER;",
                'validation_error': "ALTER TABLE config_versions ADD COLUMN validation_error TEXT;",
                'validation_error_reported_at': "ALTER TABLE config_versions ADD COLUMN validation_error_reported_at TIMESTAMP;"
            }
        }
        
        for table_name, columns in missing_columns.items():
            for col_name, alter_query in columns.items():
                try:
                    column_exists = await conn.fetchval(f"""
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name='{table_name}' AND column_name='{col_name}'
                    """)
                    if not column_exists:
                        logger.info(f"Adding missing column '{col_name}' to table '{table_name}'...")
                        await conn.execute(alter_query)
                        logger.info(f"Successfully added column '{col_name}' to '{table_name}'.")
                except Exception as col_error:
                    logger.warning(f"Could not add column '{col_name}' to '{table_name}': {col_error}")

        # Fix agents table ID issue - recreate if needed
        try:
            # Check if agents table has proper SERIAL PRIMARY KEY
            id_check = await conn.fetchval("""
                SELECT column_default FROM information_schema.columns 
                WHERE table_name='agents' AND column_name='id'
            """)
            
            if not id_check or 'nextval' not in str(id_check):
                logger.info("Agents table ID column not properly configured, recreating table...")
                # Backup existing agents data if any
                existing_agents = await conn.fetch("SELECT * FROM agents")
                logger.info(f"Found {len(existing_agents)} existing agents, backing up...")
                
                # Drop and recreate agents table with proper ID
                await conn.execute("DROP TABLE IF EXISTS agents CASCADE")
                await conn.execute("""
                    CREATE TABLE agents (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(255) UNIQUE NOT NULL,
                        pool_id INTEGER,
                        platform VARCHAR(50) DEFAULT 'linux',
                        architecture VARCHAR(50) DEFAULT 'amd64',
                        version VARCHAR(50) DEFAULT '1.0.0',
                        hostname VARCHAR(255),
                        ip_address INET,
                        operating_system VARCHAR(255),
                        kernel_version VARCHAR(255),
                        uptime INTEGER,
                        cpu_count INTEGER,
                        memory_total INTEGER,
                        disk_space INTEGER,
                        network_interfaces TEXT[],
                        capabilities TEXT[],
                        status VARCHAR(50) DEFAULT 'offline',
                        last_seen TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                logger.info("Agents table recreated with proper SERIAL PRIMARY KEY")
        except Exception as agent_fix_error:
            logger.warning(f"Could not fix agents table: {agent_fix_error}")

        # Ensure core tables exist
        tables_to_create = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(255),
                phone VARCHAR(50),
                role VARCHAR(50) DEFAULT 'user',
                is_active BOOLEAN DEFAULT TRUE,
                is_verified BOOLEAN DEFAULT FALSE,
                last_login TIMESTAMP,
                last_login_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS roles (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) UNIQUE NOT NULL,
                display_name VARCHAR(100) NOT NULL,
                description TEXT,
                permissions JSONB NOT NULL DEFAULT '{}',
                cluster_ids JSONB DEFAULT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                is_system BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS user_activity_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action VARCHAR(100) NOT NULL,
                resource_type VARCHAR(50),
                resource_id VARCHAR(100),
                details JSONB,
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS haproxy_cluster_pools (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                description TEXT,
                environment VARCHAR(50) DEFAULT 'development',
                location VARCHAR(255),
                default_config JSONB,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS haproxy_clusters (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                description TEXT,
                connection_type VARCHAR(50) DEFAULT 'agent',
                stats_socket_path VARCHAR(500) DEFAULT '/run/haproxy/admin.sock',
                haproxy_config_path VARCHAR(500) DEFAULT '/etc/haproxy/haproxy.cfg',
                pool_id INTEGER REFERENCES haproxy_cluster_pools(id) ON DELETE SET NULL,
                haproxy_user VARCHAR(255) DEFAULT 'haproxy',
                haproxy_group VARCHAR(255) DEFAULT 'haproxy',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS agents (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                pool_id INTEGER REFERENCES haproxy_cluster_pools(id) ON DELETE CASCADE,
                platform VARCHAR(50) DEFAULT 'linux',
                architecture VARCHAR(50) DEFAULT 'amd64',
                version VARCHAR(50) DEFAULT '1.0.0',
                hostname VARCHAR(255),
                ip_address INET,
                operating_system VARCHAR(255),
                kernel_version VARCHAR(255),
                uptime INTEGER,
                cpu_count INTEGER,
                memory_total INTEGER,
                disk_space INTEGER,
                network_interfaces TEXT[],
                capabilities TEXT[],
                status VARCHAR(50) DEFAULT 'offline',
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS ssl_certificates (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL UNIQUE,
                domain VARCHAR(255) NOT NULL,
                certificate_content TEXT NOT NULL,
                private_key_content TEXT NOT NULL,
                chain_content TEXT,
                expires_at TIMESTAMP,
                expiry_date DATE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS backends (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                backend_id VARCHAR(255),
                balance_method VARCHAR(50) DEFAULT 'roundrobin',
                mode VARCHAR(20) DEFAULT 'http',
                health_check_uri VARCHAR(255),
                cluster_id INTEGER,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS backend_servers (
                id SERIAL PRIMARY KEY,
                backend_name VARCHAR(100) NOT NULL,
                server_name VARCHAR(100) NOT NULL,
                server_address VARCHAR(255) NOT NULL,
                server_port INTEGER NOT NULL,
                weight INTEGER DEFAULT 100,
                check_enabled BOOLEAN DEFAULT TRUE,
                backup_server BOOLEAN DEFAULT FALSE,
                ssl_enabled BOOLEAN DEFAULT FALSE,
                cluster_id INTEGER,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS waf_rules (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL UNIQUE,
                rule_type VARCHAR(50) NOT NULL,
                action VARCHAR(20) NOT NULL DEFAULT 'block',
                priority INTEGER NOT NULL DEFAULT 100,
                is_active BOOLEAN DEFAULT TRUE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS config_versions (
                id SERIAL PRIMARY KEY,
                cluster_id INTEGER,
                version_number INTEGER NOT NULL,
                config_content TEXT NOT NULL,
                checksum VARCHAR(64),
                status VARCHAR(20) DEFAULT 'APPLIED',
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                applied_at TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS frontend_waf_rules (
                id SERIAL PRIMARY KEY,
                frontend_id INTEGER NOT NULL,
                waf_rule_id INTEGER NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (frontend_id) REFERENCES frontends(id) ON DELETE CASCADE,
                FOREIGN KEY (waf_rule_id) REFERENCES waf_rules(id) ON DELETE CASCADE
            );
            """
        ]
        
        for table_sql in tables_to_create:
            try:
                await conn.execute(table_sql)
                logger.info(f"Table created/verified successfully")
            except Exception as table_error:
                logger.warning(f"Table creation failed: {table_error}")
        
        # Specifically ensure frontend_waf_rules table exists (critical for WAF functionality)
        try:
            # First, drop the table if it exists but is malformed
            await conn.execute("DROP TABLE IF EXISTS frontend_waf_rules CASCADE")
            logger.info("Dropped existing frontend_waf_rules table if it existed")
            
            # Create the table fresh
            logger.info("Creating frontend_waf_rules table...")
            await conn.execute("""
                CREATE TABLE frontend_waf_rules (
                    id SERIAL PRIMARY KEY,
                    frontend_id INTEGER NOT NULL,
                    waf_rule_id INTEGER NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            logger.info("frontend_waf_rules table created successfully")
            
            # Verify table was created properly
            verify = await conn.fetchval("""
                SELECT COUNT(*) FROM information_schema.columns 
                WHERE table_name = 'frontend_waf_rules' AND column_name = 'frontend_id'
            """)
            
            if verify:
                logger.info("frontend_waf_rules table verified - frontend_id column exists")
            else:
                logger.error("frontend_waf_rules table creation failed - frontend_id column missing")
                
        except Exception as waf_table_error:
            logger.error(f"Failed to create frontend_waf_rules table: {waf_table_error}")
            
        # Insert initial data if not exists
        try:
            # Check if admin user exists
            admin_exists = await conn.fetchval("SELECT 1 FROM users WHERE username = 'admin'")
            if not admin_exists:
                logger.info("Creating admin user...")
                await conn.execute("""
                    INSERT INTO users (username, email, password_hash, is_admin, is_verified) 
                    VALUES ('admin', 'admin@haproxy-openmanager.local', '$2b$12$yubNpwPopBGooz/kGVyLSuQIY3u32nA4ROXveHFVvgYWMzc/K1ymS', TRUE, TRUE)
                """)
                logger.info("Admin user created successfully")
            
            # Fix host column constraint issue - make it nullable since it's not used in agent-based architecture
            try:
                await conn.execute("ALTER TABLE haproxy_clusters ALTER COLUMN host DROP NOT NULL")
                logger.info("Made host column nullable in haproxy_clusters")
            except Exception as host_error:
                logger.warning(f"Could not modify host column: {host_error}")
                
            # Add haproxy_bin_path column if it doesn't exist
            try:
                column_exists = await conn.fetchval("""
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'haproxy_clusters' AND column_name = 'haproxy_bin_path'
                """)
                if not column_exists:
                    await conn.execute("ALTER TABLE haproxy_clusters ADD COLUMN haproxy_bin_path VARCHAR(500) DEFAULT '/usr/sbin/haproxy'")
                    logger.info("Added haproxy_bin_path column to haproxy_clusters")
            except Exception as bin_path_error:
                logger.warning(f"Could not add haproxy_bin_path column: {bin_path_error}")
            
            # Add server status tracking columns to backend_servers
            try:
                # Add haproxy_status column for real-time server status from agents
                haproxy_status_exists = await conn.fetchval("""
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'backend_servers' AND column_name = 'haproxy_status'
                """)
                if not haproxy_status_exists:
                    await conn.execute("ALTER TABLE backend_servers ADD COLUMN haproxy_status VARCHAR(20) DEFAULT NULL")
                    logger.info("Added haproxy_status column to backend_servers table")
                
                # Add haproxy_status_updated_at column for tracking status freshness
                status_updated_exists = await conn.fetchval("""
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'backend_servers' AND column_name = 'haproxy_status_updated_at'
                """)
                if not status_updated_exists:
                    await conn.execute("ALTER TABLE backend_servers ADD COLUMN haproxy_status_updated_at TIMESTAMP DEFAULT NULL")
                    logger.info("Added haproxy_status_updated_at column to backend_servers table")
                
                # Create index for faster status lookups
                index_exists = await conn.fetchval("""
                    SELECT 1 FROM pg_indexes 
                    WHERE indexname = 'idx_backend_servers_status_lookup'
                """)
                if not index_exists:
                    await conn.execute("""
                        CREATE INDEX idx_backend_servers_status_lookup 
                        ON backend_servers(backend_name, cluster_id, haproxy_status_updated_at)
                    """)
                    logger.info("Created index idx_backend_servers_status_lookup on backend_servers")
                    
            except Exception as status_error:
                logger.warning(f"Could not add server status tracking columns: {status_error}")
                
            # Default records removed - users will create their own pools and clusters as needed
                
        except Exception as data_error:
            logger.warning(f"Could not insert initial data: {data_error}")
            
        # Create initial system roles and users if they don't exist
        await create_initial_system_data(conn)
        
        logger.info("Database schema check/update completed successfully.")

    except Exception as e:
        logger.error(f"Database schema check/update failed: {e}", exc_info=True)
        raise
    finally:
        if conn:
            await close_database_connection(conn)

async def ensure_config_versions_metadata_column():
    """Add metadata column to config_versions table for storing pre-apply snapshots."""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if metadata column exists
        metadata_column_exists = await conn.fetchval("""
            SELECT 1 FROM information_schema.columns 
            WHERE table_name='config_versions' AND column_name='metadata'
        """)
        
        if not metadata_column_exists:
            logger.info("Adding metadata column to config_versions table...")
            await conn.execute("ALTER TABLE config_versions ADD COLUMN metadata JSONB;")
            logger.info("Successfully added metadata column to config_versions.")
        else:
            logger.info("Metadata column already exists in config_versions table.")
            
    except Exception as e:
        logger.error(f"Error ensuring config_versions metadata column: {e}")
        raise e
    finally:
        if conn:
            await close_database_connection(conn)

async def ensure_user_pool_access_table():
    """Ensure user_pool_access table exists for multi-cluster access control"""
    conn = await get_database_connection()
    try:
        # Check if table exists
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'user_pool_access'
            )
        """)
        
        if not table_exists:
            logger.info("Creating user_pool_access table...")
            await conn.execute("""
                CREATE TABLE user_pool_access (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    pool_id INTEGER REFERENCES haproxy_cluster_pools(id) ON DELETE CASCADE,
                    access_level VARCHAR(20) DEFAULT 'read_write',
                    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    granted_by INTEGER REFERENCES users(id),
                    is_active BOOLEAN DEFAULT TRUE,
                    expires_at TIMESTAMP NULL,
                    UNIQUE(user_id, pool_id)
                );
            """)
            
            # Create indexes
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_user_pool_access_user ON user_pool_access(user_id);
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_user_pool_access_pool ON user_pool_access(pool_id);
            """)
            
            # Grant admin user access to all existing pools
            await conn.execute("""
                INSERT INTO user_pool_access (user_id, pool_id, access_level, granted_by)
                SELECT u.id, p.id, 'admin', u.id
                FROM users u, haproxy_cluster_pools p
                WHERE u.username = 'admin' AND u.is_admin = TRUE
                ON CONFLICT (user_id, pool_id) DO NOTHING;
            """)
            
            logger.info("✅ user_pool_access table created successfully with admin access")
        else:
            logger.info("user_pool_access table already exists")
            
    except Exception as e:
        logger.error(f"Failed to create user_pool_access table: {e}")
        raise
    finally:
        await close_database_connection(conn)

async def ensure_backend_servers_last_config_status():
    """Add last_config_status column to backend_servers table"""
    conn = await get_database_connection()
    try:
        # Check if column exists
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'backend_servers' 
                AND column_name = 'last_config_status'
            );
        """)
        
        if not column_exists:
            logger.info("Adding last_config_status column to backend_servers table...")
            await conn.execute("""
                ALTER TABLE backend_servers 
                ADD COLUMN last_config_status VARCHAR(20) DEFAULT 'APPLIED'
            """)
            
            # Update existing servers to APPLIED status
            await conn.execute("""
                UPDATE backend_servers 
                SET last_config_status = 'APPLIED' 
                WHERE last_config_status IS NULL
            """)
            
            logger.info("Successfully added last_config_status column to backend_servers table")
        else:
            logger.info("last_config_status column already exists in backend_servers table")
            
    except Exception as e:
        logger.error(f"Error adding last_config_status column to backend_servers: {e}")
        raise
    finally:
        await close_database_connection(conn)

async def ensure_backend_servers_haproxy_status():
    """Add haproxy_status and haproxy_status_updated_at columns to backend_servers table"""
    conn = await get_database_connection()
    try:
        # Check if columns exist
        haproxy_status_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'backend_servers' 
                AND column_name = 'haproxy_status'
            );
        """)
        
        haproxy_status_updated_at_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'backend_servers' 
                AND column_name = 'haproxy_status_updated_at'
            );
        """)
        
        if not haproxy_status_exists:
            logger.info("Adding haproxy_status column to backend_servers table...")
            await conn.execute("""
                ALTER TABLE backend_servers 
                ADD COLUMN haproxy_status VARCHAR(20) DEFAULT 'UNKNOWN'
            """)
            logger.info("Successfully added haproxy_status column to backend_servers table")
        else:
            logger.info("haproxy_status column already exists in backend_servers table")
            
        if not haproxy_status_updated_at_exists:
            logger.info("Adding haproxy_status_updated_at column to backend_servers table...")
            await conn.execute("""
                ALTER TABLE backend_servers 
                ADD COLUMN haproxy_status_updated_at TIMESTAMP
            """)
            logger.info("Successfully added haproxy_status_updated_at column to backend_servers table")
        else:
            logger.info("haproxy_status_updated_at column already exists in backend_servers table")
            
    except Exception as e:
        logger.error(f"Error adding haproxy_status columns to backend_servers: {e}")
        raise
    finally:
        await close_database_connection(conn)

async def ensure_ssl_certificates_new_columns():
    """Ensure ssl_certificates table has new schema columns"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if ssl_certificates table exists
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'ssl_certificates'
            )
        """)
        
        if not table_exists:
            logger.info("ssl_certificates table does not exist, skipping migration")
            return
        
        # Add missing columns if they don't exist
        columns_to_add = [
            ("issuer", "VARCHAR(255)"),
            ("fingerprint", "VARCHAR(128)"),
            ("status", "VARCHAR(20) DEFAULT 'valid'"),
            ("days_until_expiry", "INTEGER DEFAULT 0"),
            ("all_domains", "JSONB DEFAULT '[]'")
        ]
        
        for column_name, column_def in columns_to_add:
            column_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'ssl_certificates' AND column_name = $1
                )
            """, column_name)
            
            if not column_exists:
                await conn.execute(f"""
                    ALTER TABLE ssl_certificates 
                    ADD COLUMN {column_name} {column_def}
                """)
                logger.info(f"Added column '{column_name}' to ssl_certificates table")
        
        # Update existing certificates to have valid status
        await conn.execute("""
            UPDATE ssl_certificates 
            SET status = 'valid' 
            WHERE status IS NULL
        """)
        
        logger.info("SSL certificates table schema updated successfully")
        
    except Exception as e:
        logger.error(f"Failed to update ssl_certificates schema: {e}")
        raise
    finally:
        if conn:
            await close_database_connection(conn)

async def ensure_ssl_cluster_junction_table():
    """Create SSL-Cluster many-to-many junction table"""
    try:
        conn = await get_database_connection()
        
        # Create ssl_certificate_clusters junction table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ssl_certificate_clusters (
                id SERIAL PRIMARY KEY,
                ssl_certificate_id INTEGER NOT NULL REFERENCES ssl_certificates(id) ON DELETE CASCADE,
                cluster_id INTEGER NOT NULL REFERENCES haproxy_clusters(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ssl_certificate_id, cluster_id)
            )
        """)
        
        # Migrate existing ssl_certificates.cluster_id data to junction table
        existing_mappings = await conn.fetch("""
            SELECT id, cluster_id FROM ssl_certificates 
            WHERE cluster_id IS NOT NULL
        """)
        
        for mapping in existing_mappings:
            # Insert into junction table if not exists
            await conn.execute("""
                INSERT INTO ssl_certificate_clusters (ssl_certificate_id, cluster_id)
                VALUES ($1, $2)
                ON CONFLICT (ssl_certificate_id, cluster_id) DO NOTHING
            """, mapping['id'], mapping['cluster_id'])
        
        await close_database_connection(conn)
        logger.info("✅ SSL-Cluster junction table migration completed")
        
    except Exception as e:
        logger.error(f"❌ SSL-Cluster junction table migration failed: {e}")
        if conn:
            await close_database_connection(conn)
        raise

async def fix_backend_unique_constraint():
    """Fix backend name unique constraint to be cluster-specific"""
    conn = None
    try:
        conn = await get_database_connection()
        logger.info("🔧 Starting backend unique constraint migration...")
        
        # Check if global unique constraint exists
        constraint_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.table_constraints 
                WHERE table_name = 'backends' 
                AND constraint_name = 'backends_name_key'
                AND constraint_type = 'UNIQUE'
            )
        """)
        
        if constraint_exists:
            logger.info("📝 Dropping global unique constraint on backends.name...")
            await conn.execute("ALTER TABLE backends DROP CONSTRAINT IF EXISTS backends_name_key")
            
            # Check if cluster-specific unique constraint already exists
            cluster_constraint_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.table_constraints 
                    WHERE table_name = 'backends' 
                    AND constraint_name = 'backends_name_cluster_unique'
                    AND constraint_type = 'UNIQUE'
                )
            """)
            
            if not cluster_constraint_exists:
                logger.info("➕ Adding cluster-specific unique constraint on backends (name, cluster_id)...")
                await conn.execute("""
                    ALTER TABLE backends 
                    ADD CONSTRAINT backends_name_cluster_unique 
                    UNIQUE (name, cluster_id)
                """)
                logger.info("✅ Backend unique constraint fixed successfully")
            else:
                logger.info("ℹ️ Cluster-specific unique constraint already exists")
        else:
            logger.info("ℹ️ Global unique constraint on backends.name does not exist")
            
        await close_database_connection(conn)
        logger.info("✅ Backend unique constraint migration completed")
        
    except Exception as e:
        logger.error(f"❌ Backend unique constraint migration failed: {e}")
        if conn:
            await close_database_connection(conn)
        raise

async def fix_frontend_unique_constraint():
    """Fix frontend name unique constraint to be cluster-specific"""
    conn = None
    try:
        conn = await get_database_connection()
        logger.info("🔧 Starting frontend unique constraint migration...")
        
        # Check if global unique constraint exists
        constraint_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.table_constraints 
                WHERE table_name = 'frontends' 
                AND constraint_name = 'frontends_name_key'
                AND constraint_type = 'UNIQUE'
            )
        """)
        
        if constraint_exists:
            logger.info("📝 Dropping global unique constraint on frontends.name...")
            await conn.execute("ALTER TABLE frontends DROP CONSTRAINT IF EXISTS frontends_name_key")
            
            # Check if cluster-specific unique constraint already exists
            cluster_constraint_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.table_constraints 
                    WHERE table_name = 'frontends' 
                    AND constraint_name = 'frontends_name_cluster_unique'
                    AND constraint_type = 'UNIQUE'
                )
            """)
            
            if not cluster_constraint_exists:
                logger.info("➕ Adding cluster-specific unique constraint on frontends (name, cluster_id)...")
                await conn.execute("""
                    ALTER TABLE frontends 
                    ADD CONSTRAINT frontends_name_cluster_unique 
                    UNIQUE (name, cluster_id)
                """)
                logger.info("✅ Frontend unique constraint fixed successfully")
            else:
                logger.info("ℹ️ Cluster-specific unique constraint already exists")
        else:
            logger.info("ℹ️ Global unique constraint on frontends.name does not exist")
            
        await close_database_connection(conn)
        logger.info("✅ Frontend unique constraint migration completed")
        
    except Exception as e:
        logger.error(f"❌ Frontend unique constraint migration failed: {e}")
        if conn:
            await close_database_connection(conn)
        raise

async def fix_waf_unique_constraint():
    """Fix WAF rules name unique constraint to be cluster-specific"""
    conn = None
    try:
        conn = await get_database_connection()
        logger.info("🔧 Starting WAF rules unique constraint migration...")
        
        # Check if global unique constraint exists
        constraint_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.table_constraints 
                WHERE table_name = 'waf_rules' 
                AND constraint_name = 'waf_rules_name_key'
                AND constraint_type = 'UNIQUE'
            )
        """)
        
        if constraint_exists:
            logger.info("📝 Dropping global unique constraint on waf_rules.name...")
            await conn.execute("ALTER TABLE waf_rules DROP CONSTRAINT IF EXISTS waf_rules_name_key")
            
            # Check if cluster-specific unique constraint already exists
            cluster_constraint_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.table_constraints 
                    WHERE table_name = 'waf_rules' 
                    AND constraint_name = 'waf_rules_name_cluster_unique'
                    AND constraint_type = 'UNIQUE'
                )
            """)
            
            if not cluster_constraint_exists:
                logger.info("➕ Adding cluster-specific unique constraint on waf_rules (name, cluster_id)...")
                await conn.execute("""
                    ALTER TABLE waf_rules 
                    ADD CONSTRAINT waf_rules_name_cluster_unique 
                    UNIQUE (name, cluster_id)
                """)
                logger.info("✅ WAF rules unique constraint fixed successfully")
            else:
                logger.info("ℹ️ Cluster-specific unique constraint already exists")
        else:
            logger.info("ℹ️ Global unique constraint on waf_rules.name does not exist")
            
        await close_database_connection(conn)
        logger.info("✅ WAF rules unique constraint migration completed")
        
    except Exception as e:
        logger.error(f"❌ WAF rules unique constraint migration failed: {e}")
        if conn:
            await close_database_connection(conn)
        raise

async def fix_backend_servers_unique_constraint():
    """Fix backend servers unique constraint to be cluster-specific"""
    conn = None
    try:
        conn = await get_database_connection()
        logger.info("🔧 Starting backend servers unique constraint migration...")
        
        # Check if cluster-specific unique constraint already exists
        constraint_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.table_constraints 
                WHERE table_name = 'backend_servers' 
                AND constraint_name = 'backend_servers_backend_name_server_name_cluster_id_key'
                AND constraint_type = 'UNIQUE'
            )
        """)
        
        if not constraint_exists:
            logger.info("➕ Adding cluster-specific unique constraint on backend_servers (backend_name, server_name, cluster_id)...")
            await conn.execute("""
                ALTER TABLE backend_servers 
                ADD CONSTRAINT backend_servers_backend_name_server_name_cluster_id_key 
                UNIQUE (backend_name, server_name, cluster_id)
            """)
            logger.info("✅ Backend servers unique constraint added successfully")
        else:
            logger.info("ℹ️ Cluster-specific unique constraint already exists")
            
        await close_database_connection(conn)
        logger.info("✅ Backend servers unique constraint migration completed")
        
    except Exception as e:
        logger.error(f"❌ Backend servers unique constraint migration failed: {e}")
        if conn:
            await close_database_connection(conn)
        raise


async def add_frontend_ssl_port_column():
    """Add ssl_port column to frontends table"""
    conn = None
    try:
        conn = await get_database_connection()
        logger.info("🔧 Starting frontend ssl_port column migration...")
        
        # Check if ssl_port column exists
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'frontends' 
                AND column_name = 'ssl_port'
            )
        """)
        
        if not column_exists:
            logger.info("➕ Adding ssl_port column to frontends table...")
            await conn.execute("ALTER TABLE frontends ADD COLUMN ssl_port INTEGER")
            logger.info("✅ ssl_port column added successfully")
        else:
            logger.info("ℹ️ ssl_port column already exists")
            
        await close_database_connection(conn)
        logger.info("✅ Frontend ssl_port column migration completed")
        
    except Exception as e:
        logger.error(f"❌ Frontend ssl_port column migration failed: {e}")
        if conn:
            await close_database_connection(conn)
        raise

async def add_config_versions_updated_at_column():
    """Add updated_at column to config_versions table"""
    conn = None
    try:
        conn = await get_database_connection()
        logger.info("🔧 Starting config_versions updated_at column migration...")
        
        # Check if updated_at column exists
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'config_versions' 
                AND column_name = 'updated_at'
            )
        """)
        
        if not column_exists:
            logger.info("➕ Adding updated_at column to config_versions table...")
            await conn.execute("""
                ALTER TABLE config_versions 
                ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            """)
            logger.info("✅ updated_at column added successfully")
        else:
            logger.info("ℹ️ updated_at column already exists")
            
        await close_database_connection(conn)
        logger.info("✅ Config versions updated_at column migration completed")
        
    except Exception as e:
        logger.error(f"❌ Config versions updated_at column migration failed: {e}")
        if conn:
            await close_database_connection(conn)
        raise

async def ensure_roles_cluster_ids_column():
    """Add cluster_ids JSONB column to roles table for cluster-specific roles"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if cluster_ids column exists
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'roles' AND column_name = 'cluster_ids'
            )
        """)
        
        if not column_exists:
            logger.info("Adding cluster_ids column to roles table...")
            await conn.execute("""
                ALTER TABLE roles 
                ADD COLUMN cluster_ids JSONB DEFAULT NULL
            """)
            logger.info("Successfully added cluster_ids column to roles table")
        
        await close_database_connection(conn)
        
    except Exception as e:
        logger.error(f"Failed to add cluster_ids column to roles: {e}")
        if conn:
            await close_database_connection(conn)
        # Don't raise - this is not critical for system operation

async def update_system_roles_to_enterprise_rbac():
    """Update system roles to new enterprise RBAC permissions structure"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Define enterprise permissions for each role
        enterprise_roles = {
            'super_admin': {
                'display_name': 'Super Administrator',
                'description': 'Full system access with all permissions',
                'permissions': [
                    # All permissions - full access
                    'dashboard.read', 'dashboard.statistics', 'dashboard.metrics',
                    'frontends.read', 'frontends.create', 'frontends.update', 'frontends.delete', 'frontends.toggle', 'frontends.history',
                    'backends.read', 'backends.create', 'backends.update', 'backends.delete', 'backends.toggle', 'backends.servers', 'backends.history',
                    'waf.read', 'waf.create', 'waf.update', 'waf.delete', 'waf.toggle', 'waf.history',
                    'ssl.read', 'ssl.create', 'ssl.update', 'ssl.delete', 'ssl.download', 'ssl.history',
                    'apply.read', 'apply.execute', 'apply.reject', 'apply.history', 'apply.bulk', 'apply.emergency',
                    'agents.read', 'agents.create', 'agents.update', 'agents.delete', 'agents.script', 'agents.toggle', 'agents.upgrade', 'agents.version', 'agents.logs',
                    'clusters.read', 'clusters.create', 'clusters.update', 'clusters.delete', 'clusters.switch', 'clusters.config',
                    'config.read', 'config.update', 'config.download', 'config.upload', 'config.backup', 'config.restore', 'config.history', 'config.bulk_import', 'config.view_request', 'config.download_request',
                    'users.read', 'users.create', 'users.update', 'users.delete', 'users.password', 'users.roles',
                    'roles.read', 'roles.create', 'roles.update', 'roles.delete', 'roles.permissions',
                    'statistics.read', 'statistics.performance', 'statistics.agents', 'statistics.health', 'statistics.export',
                    'activity.read', 'activity.all', 'activity.export',
                    'settings.read', 'settings.update', 'settings.system', 'settings.security',
                    'system.restart', 'system.logs', 'system.database', 'system.services', 'system.emergency'
                ]
            },
            'operator': {
                'display_name': 'Operator',
                'description': 'Daily operational access for managing HAProxy configurations and applying changes',
                'permissions': [
                    'dashboard.read', 'dashboard.statistics', 'dashboard.metrics',
                    'frontends.read', 'frontends.create', 'frontends.update', 'frontends.delete', 'frontends.toggle', 'frontends.history',
                    'backends.read', 'backends.create', 'backends.update', 'backends.delete', 'backends.toggle', 'backends.servers', 'backends.history',
                    'waf.read', 'waf.create', 'waf.update', 'waf.delete', 'waf.toggle', 'waf.history',
                    'ssl.read', 'ssl.create', 'ssl.update', 'ssl.delete', 'ssl.download', 'ssl.history',
                    'apply.read', 'apply.execute', 'apply.reject', 'apply.history', 'apply.bulk',
                    'agents.read', 'agents.update', 'agents.toggle', 'agents.upgrade', 'agents.version', 'agents.logs',
                    'clusters.read', 'clusters.switch', 'clusters.config',
                    'config.read', 'config.update', 'config.download', 'config.history', 'config.bulk_import', 'config.view_request', 'config.download_request',
                    'statistics.read', 'statistics.performance', 'statistics.agents', 'statistics.health',
                    'activity.read'
                ]
            },
            'security_admin': {
                'display_name': 'Security Administrator',
                'description': 'Security-focused access for WAF rules, SSL certificates, and security monitoring',
                'permissions': [
                    'dashboard.read', 'dashboard.statistics', 'dashboard.metrics',
                    'frontends.read', 'frontends.history',
                    'backends.read', 'backends.history',
                    'waf.read', 'waf.create', 'waf.update', 'waf.delete', 'waf.toggle', 'waf.history',
                    'ssl.read', 'ssl.create', 'ssl.update', 'ssl.delete', 'ssl.download', 'ssl.history',
                    'apply.read', 'apply.execute', 'apply.reject', 'apply.history',
                    'agents.read', 'agents.version', 'agents.logs',
                    'clusters.read', 'clusters.switch',
                    'config.read', 'config.history', 'config.view_request', 'config.download_request',
                    'statistics.read', 'statistics.performance', 'statistics.agents', 'statistics.health',
                    'activity.read', 'activity.all', 'activity.export',
                    'settings.read', 'settings.security'
                ]
            },
            'viewer': {
                'display_name': 'Viewer',
                'description': 'Read-only access to view configurations, statistics, and monitor system status',
                'permissions': [
                    'dashboard.read', 'dashboard.statistics', 'dashboard.metrics',
                    'frontends.read', 'frontends.history',
                    'backends.read', 'backends.history',
                    'waf.read', 'waf.history',
                    'ssl.read', 'ssl.history',
                    'apply.read', 'apply.history',
                    'agents.read',
                    'clusters.read', 'clusters.switch',
                    'config.read', 'config.history', 'config.view_request',
                    'statistics.read', 'statistics.performance', 'statistics.agents', 'statistics.health',
                    'activity.read',
                    'settings.read'
                ]
            }
        }
        
        # Update each system role
        for role_name, role_data in enterprise_roles.items():
            try:
                # Check if role exists
                role_exists = await conn.fetchval("""
                    SELECT id FROM roles WHERE name = $1
                """, role_name)
                
                if role_exists:
                    # Update existing role
                    await conn.execute("""
                        UPDATE roles SET 
                            display_name = $1,
                            description = $2,
                            permissions = $3,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE name = $4
                    """, 
                        role_data['display_name'],
                        role_data['description'],
                        json.dumps(role_data['permissions']),
                        role_name
                    )
                    logger.info(f"✅ Updated system role: {role_name} with {len(role_data['permissions'])} permissions")
                else:
                    # Create new role
                    await conn.execute("""
                        INSERT INTO roles (name, display_name, description, permissions, is_active, is_system)
                        VALUES ($1, $2, $3, $4, $5, $6)
                    """, 
                        role_name,
                        role_data['display_name'],
                        role_data['description'],
                        json.dumps(role_data['permissions']),
                        True,
                        True
                    )
                    logger.info(f"✅ Created system role: {role_name} with {len(role_data['permissions'])} permissions")
                    
            except Exception as role_error:
                logger.warning(f"Failed to update role {role_name}: {role_error}")
        
        # Ensure default users exist with correct roles
        default_users = {
            'admin': {
                'email': 'admin@haproxy-openmanager.local',
                'full_name': 'System Administrator',
                'phone': '+1-555-0001',
                'role': 'super_admin',
                'is_admin': True
            },
            'operator1': {
                'email': 'operator@haproxy-openmanager.local', 
                'full_name': 'Daily Operator',
                'phone': '+1-555-0101',
                'role': 'operator',
                'is_admin': False
            },
            'security1': {
                'email': 'security@haproxy-openmanager.local',
                'full_name': 'Security Analyst', 
                'phone': '+1-555-0102',
                'role': 'security_admin',
                'is_admin': False
            },
            'viewer1': {
                'email': 'viewer@haproxy-openmanager.local',
                'full_name': 'Read Only User',
                'phone': '+1-555-0103', 
                'role': 'viewer',
                'is_admin': False
            }
        }
        
        # Default password hash for all users: admin123
        password_hash = '$2b$12$yubNpwPopBGooz/kGVyLSuQIY3u32nA4ROXveHFVvgYWMzc/K1ymS'
        
        for username, user_data in default_users.items():
            try:
                # Check if user exists
                user_exists = await conn.fetchval("""
                    SELECT id FROM users WHERE username = $1
                """, username)
                
                if not user_exists:
                    # Create user
                    user_id = await conn.fetchval("""
                        INSERT INTO users (username, email, password_hash, full_name, phone, is_active, is_admin, is_verified)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        RETURNING id
                    """, 
                        username,
                        user_data['email'],
                        password_hash,
                        user_data['full_name'],
                        user_data['phone'],
                        True,  # is_active
                        user_data['is_admin'],
                        True   # is_verified
                    )
                    logger.info(f"✅ Created default user: {username}")
                else:
                    user_id = user_exists
                    logger.info(f"✅ Default user already exists: {username}")
                
                # Assign role to user
                role_id = await conn.fetchval("""
                    SELECT id FROM roles WHERE name = $1
                """, user_data['role'])
                
                if role_id:
                    # Check if role assignment exists
                    assignment_exists = await conn.fetchval("""
                        SELECT id FROM user_roles WHERE user_id = $1 AND role_id = $2
                    """, user_id, role_id)
                    
                    if not assignment_exists:
                        await conn.execute("""
                            INSERT INTO user_roles (user_id, role_id, assigned_by)
                            VALUES ($1, $2, $3)
                        """, user_id, role_id, 1)  # Assigned by admin (id=1)
                        logger.info(f"✅ Assigned role {user_data['role']} to user {username}")
                    
            except Exception as user_error:
                logger.warning(f"Failed to create/update user {username}: {user_error}")
        
        await close_database_connection(conn)
        logger.info("✅ Enterprise RBAC system roles and users migration completed")
        
    except Exception as e:
        logger.error(f"Failed to update system roles to enterprise RBAC: {e}")
        if conn:
            await close_database_connection(conn)
        # Don't raise - this is not critical for system operation

async def ensure_user_activity_logs_table():
    """Ensure user_activity_logs table exists with proper schema"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if table exists
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'user_activity_logs'
            )
        """)
        
        if not table_exists:
            logger.info("Creating user_activity_logs table...")
            await conn.execute("""
                CREATE TABLE user_activity_logs (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    action VARCHAR(100) NOT NULL,
                    resource_type VARCHAR(50),
                    resource_id VARCHAR(100),
                    details JSONB,
                    ip_address INET,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
            # Create indexes for better performance
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_user_activity_logs_user_id ON user_activity_logs(user_id);
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_user_activity_logs_created_at ON user_activity_logs(created_at DESC);
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_user_activity_logs_resource ON user_activity_logs(resource_type, resource_id);
            """)
            
            logger.info("Successfully created user_activity_logs table with indexes")
        else:
            logger.info("user_activity_logs table already exists")
            
            # Ensure all required columns exist
            required_columns = {
                'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
                'ip_address': 'INET',
                'user_agent': 'TEXT',
                'details': 'JSONB'
            }
            
            for column_name, column_type in required_columns.items():
                column_exists = await conn.fetchval("""
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'user_activity_logs' AND column_name = $1
                    )
                """, column_name)
                
                if not column_exists:
                    logger.info(f"Adding missing column {column_name} to user_activity_logs table...")
                    await conn.execute(f"""
                        ALTER TABLE user_activity_logs 
                        ADD COLUMN {column_name} {column_type}
                    """)
        
        await close_database_connection(conn)
        logger.info("✅ user_activity_logs table migration completed")
        
    except Exception as e:
        logger.error(f"Failed to ensure user_activity_logs table: {e}")
        if conn:
            await close_database_connection(conn)
        # Don't raise - this is not critical for system operation

async def ensure_agent_activity_logs_table():
    """Create agent_activity_logs table for tracking meaningful agent actions"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if table exists
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'agent_activity_logs'
            )
        """)
        
        if not table_exists:
            logger.info("Creating agent_activity_logs table...")
            await conn.execute("""
                CREATE TABLE agent_activity_logs (
                    id SERIAL PRIMARY KEY,
                    agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
                    agent_name VARCHAR(255) NOT NULL,
                    action_type VARCHAR(50) NOT NULL,
                    action_details JSONB,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for performance
            await conn.execute("""
                CREATE INDEX idx_agent_activity_logs_agent_id ON agent_activity_logs(agent_id);
                CREATE INDEX idx_agent_activity_logs_agent_name ON agent_activity_logs(agent_name);
                CREATE INDEX idx_agent_activity_logs_timestamp ON agent_activity_logs(timestamp DESC);
                CREATE INDEX idx_agent_activity_logs_action_type ON agent_activity_logs(action_type);
            """)
            
            logger.info("✅ agent_activity_logs table created successfully")
        else:
            logger.info("agent_activity_logs table already exists")
        
        # Add last_action_time column to agents table
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns 
                WHERE table_name = 'agents' AND column_name = 'last_action_time'
            )
        """)
        
        if not column_exists:
            logger.info("Adding last_action_time column to agents table...")
            await conn.execute("""
                ALTER TABLE agents ADD COLUMN last_action_time TIMESTAMP;
            """)
            logger.info("✅ last_action_time column added to agents table")
        
        await close_database_connection(conn)
        
    except Exception as e:
        logger.error(f"Failed to ensure agent_activity_logs table: {e}")
        if conn:
            await close_database_connection(conn)
        # Don't raise - this is not critical for system operation

async def run_all_migrations():
    """Run all database migrations"""
    logger.info("Starting database migrations...")
    
    # First, ensure basic database schema exists
    await run_init_sql()
    
    # Then run additional migrations
    await ensure_agents_table()
    await ensure_config_versions_metadata_column()
    await ensure_user_pool_access_table()
    await ensure_backend_servers_last_config_status()
    await ensure_backend_servers_haproxy_status()
    await ensure_ssl_certificates_new_columns()
    await ensure_ssl_cluster_junction_table()
    await fix_backend_unique_constraint()
    await fix_frontend_unique_constraint()
    await fix_waf_unique_constraint()
    await fix_backend_servers_unique_constraint()
    # Enum migration removed - REJECTED value already in init.sql for fresh databases
    await add_frontend_ssl_port_column()
    await add_config_versions_updated_at_column()
    await ensure_roles_cluster_ids_column()
    await update_system_roles_to_enterprise_rbac()
    await ensure_user_activity_logs_table()
    await ensure_agent_api_key_columns()
    await ensure_frontends_ssl_columns()
    await ensure_validation_error_columns()
    await remove_haproxy_user_group_columns()
    await ensure_agent_versions_table()
    await ensure_agent_script_templates_table()
    await ensure_agent_activity_logs_table()
    await ensure_agent_config_management_tables()
    await fix_users_unique_constraints_for_soft_delete()
    
    logger.info("Database migrations completed successfully.")

async def remove_haproxy_user_group_columns():
    """Remove haproxy_user and haproxy_group columns from haproxy_clusters table"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if columns exist before trying to drop them
        user_column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'haproxy_clusters' 
                AND column_name = 'haproxy_user'
            )
        """)
        
        group_column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'haproxy_clusters' 
                AND column_name = 'haproxy_group'
            )
        """)
        
        if user_column_exists:
            await conn.execute("ALTER TABLE haproxy_clusters DROP COLUMN haproxy_user")
            logger.info("✅ Dropped haproxy_user column from haproxy_clusters")
        else:
            logger.info("ℹ️  haproxy_user column already removed")
            
        if group_column_exists:
            await conn.execute("ALTER TABLE haproxy_clusters DROP COLUMN haproxy_group")
            logger.info("✅ Dropped haproxy_group column from haproxy_clusters")
        else:
            logger.info("ℹ️  haproxy_group column already removed")
        
        logger.info("✅ HAProxy user/group columns removal completed")
        
    except Exception as e:
        logger.error(f"❌ Failed to remove HAProxy user/group columns: {e}")
        raise
    finally:
        if conn:
            await close_database_connection(conn)

async def ensure_agent_api_key_columns():
    """Add API key columns to agents table for secure agent authentication"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if api_key column exists
        api_key_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'agents' AND column_name = 'api_key'
            )
        """)
        
        if not api_key_exists:
            logger.info("Adding api_key column to agents table...")
            await conn.execute("""
                ALTER TABLE agents 
                ADD COLUMN api_key VARCHAR(128),
                ADD COLUMN api_key_name VARCHAR(100),
                ADD COLUMN api_key_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ADD COLUMN api_key_expires_at TIMESTAMP,
                ADD COLUMN api_key_last_used TIMESTAMP,
                ADD COLUMN api_key_created_by INTEGER REFERENCES users(id)
            """)
            
            # Create index for fast API key lookups
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agents_api_key ON agents(api_key) WHERE api_key IS NOT NULL;
            """)
            
            logger.info("Successfully added API key columns to agents table")
        else:
            logger.info("API key columns already exist in agents table")
        
        await close_database_connection(conn)
        logger.info("✅ Agent API key columns migration completed")
        
    except Exception as e:
        logger.error(f"Failed to add agent API key columns: {e}")
        if conn:
            await close_database_connection(conn)

async def create_initial_system_data(conn):
    """Create initial system roles and users"""
    try:
        # Create system roles with basic permissions (cluster_ids will be added later)
        system_roles = [
            {
                'name': 'super_admin',
                'display_name': 'Super Administrator', 
                'description': 'Full system access with all permissions',
                'permissions': ["dashboard.read","dashboard.statistics","frontends.read","frontends.create","frontends.update","frontends.delete","backends.read","backends.create","backends.update","backends.delete","waf.read","waf.create","waf.update","waf.delete","ssl.read","ssl.create","ssl.update","ssl.delete","apply.read","apply.execute","agents.read","agents.create","agents.update","agents.delete","clusters.read","clusters.create","clusters.update","clusters.delete","config.read","config.update","config.bulk_import","config.view_request","config.download_request","users.read","users.create","users.update","users.delete","roles.read","roles.create","roles.update","roles.delete"]
            },
            {
                'name': 'operator',
                'display_name': 'Operator',
                'description': 'Daily operational access for managing HAProxy configurations',
                'permissions': ["dashboard.read","dashboard.statistics","frontends.read","frontends.create","frontends.update","backends.read","backends.create","backends.update","waf.read","waf.create","waf.update","ssl.read","ssl.create","ssl.update","apply.read","apply.execute","agents.read","clusters.read","config.read","config.update","config.bulk_import","config.view_request","config.download_request"]
            },
            {
                'name': 'security_admin',
                'display_name': 'Security Administrator',
                'description': 'Security-focused access for WAF rules and SSL certificates',
                'permissions': ["dashboard.read","frontends.read","backends.read","waf.read","waf.create","waf.update","waf.delete","ssl.read","ssl.create","ssl.update","ssl.delete","apply.read","apply.execute","agents.read","clusters.read","config.read","config.view_request","config.download_request"]
            },
            {
                'name': 'viewer',
                'display_name': 'Viewer',
                'description': 'Read-only access to view configurations and monitor system status',
                'permissions': ["dashboard.read","frontends.read","backends.read","waf.read","ssl.read","apply.read","agents.read","clusters.read","config.read","config.view_request"]
            }
        ]
        
        for role_data in system_roles:
            await conn.execute("""
                INSERT INTO roles (name, display_name, description, permissions, is_active, is_system)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (name) DO NOTHING
            """, 
                role_data['name'],
                role_data['display_name'],
                role_data['description'],
                role_data['permissions'],  # Direct list, not JSON string
                True,
                True
            )
        
        logger.info("✅ System roles created")
        
        # Create default admin user
        import bcrypt
        password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        admin_id = await conn.fetchval("""
            INSERT INTO users (username, email, password_hash, full_name, is_active, is_admin, is_verified)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (username) DO NOTHING
            RETURNING id
        """, 'admin', 'admin@haproxy-openmanager.local', password_hash, 'System Administrator', True, True, True)
        
        if admin_id:
            # Assign super_admin role to admin user
            super_admin_role = await conn.fetchval("SELECT id FROM roles WHERE name = 'super_admin'")
            if super_admin_role:
                await conn.execute("""
                    INSERT INTO user_roles (user_id, role_id, assigned_by)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (user_id, role_id) DO NOTHING
                """, admin_id, super_admin_role, admin_id)
            
            logger.info("✅ Default admin user created")
        else:
            logger.info("✅ Default admin user already exists")
            
    except Exception as e:
        logger.error(f"Failed to create initial system data: {e}")
        raise

async def create_essential_tables(conn):
    """Create all essential tables if they don't exist"""
    try:
        # Create enum types first
        await conn.execute("""
            DO $$ BEGIN
                CREATE TYPE config_status AS ENUM ('PENDING', 'APPLIED', 'REJECTED');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
        """)
        
        # Create users table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100),
                phone VARCHAR(20),
                role VARCHAR(50) DEFAULT 'admin',
                is_active BOOLEAN DEFAULT TRUE,
                is_admin BOOLEAN DEFAULT FALSE,
                is_verified BOOLEAN DEFAULT FALSE,
                last_login TIMESTAMP,
                last_login_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Create roles table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) UNIQUE NOT NULL,
                display_name VARCHAR(100) NOT NULL,
                description TEXT,
                permissions JSONB DEFAULT '[]'::jsonb,
                cluster_ids JSONB DEFAULT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                is_system BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Create user_roles junction table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS user_roles (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                assigned_by INTEGER REFERENCES users(id),
                is_active BOOLEAN DEFAULT TRUE,
                UNIQUE(user_id, role_id)
            );
        """)
        
        # Create haproxy_cluster_pools table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS haproxy_cluster_pools (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                description TEXT,
                environment VARCHAR(50) DEFAULT 'development',
                location VARCHAR(255),
                default_config JSONB,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Create haproxy_clusters table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS haproxy_clusters (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                environment VARCHAR(50),
                pool_id INTEGER REFERENCES haproxy_cluster_pools(id) ON DELETE SET NULL,
                haproxy_config_path VARCHAR(255) DEFAULT '/etc/haproxy/haproxy.cfg',
                haproxy_bin_path VARCHAR(255) DEFAULT '/usr/sbin/haproxy',
                stats_socket_path VARCHAR(255) DEFAULT '/var/run/haproxy/admin.sock',
                haproxy_user VARCHAR(255) DEFAULT 'haproxy',
                haproxy_group VARCHAR(255) DEFAULT 'haproxy',
                installation_type VARCHAR(50) DEFAULT 'agent',
                deployment_type VARCHAR(50) DEFAULT 'standalone',
                host VARCHAR(255),
                port INTEGER,
                connection_type VARCHAR(50) DEFAULT 'agent',
                is_active BOOLEAN DEFAULT TRUE,
                is_default BOOLEAN DEFAULT FALSE,
                last_connected_at TIMESTAMP,
                connection_status VARCHAR(50) DEFAULT 'unknown',
                connection_error TEXT,
                haproxy_version VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, pool_id)
            );
        """)
        
        # Create config_versions table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS config_versions (
                id SERIAL PRIMARY KEY,
                cluster_id INTEGER REFERENCES haproxy_clusters(id) ON DELETE CASCADE,
                version_name VARCHAR(100) NOT NULL,
                description TEXT,
                config_content TEXT NOT NULL,
                checksum VARCHAR(64),
                file_size INTEGER,
                status config_status DEFAULT 'APPLIED',
                metadata JSONB DEFAULT '{}'::jsonb,
                is_active BOOLEAN DEFAULT TRUE,
                created_by INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(cluster_id, version_name)
            );
        """)
        
        # Create agents table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                hostname VARCHAR(255),
                ip_address INET,
                platform VARCHAR(50),
                architecture VARCHAR(50),
                version VARCHAR(50),
                operating_system VARCHAR(100),
                kernel_version VARCHAR(100),
                uptime BIGINT,
                cpu_count INTEGER,
                memory_total BIGINT,
                disk_space BIGINT,
                network_interfaces JSONB DEFAULT '[]'::jsonb,
                capabilities JSONB DEFAULT '[]'::jsonb,
                status VARCHAR(20) DEFAULT 'offline',
                haproxy_status VARCHAR(20) DEFAULT 'unknown',
                haproxy_version VARCHAR(50),
                pool_id INTEGER REFERENCES haproxy_cluster_pools(id) ON DELETE SET NULL,
                enabled BOOLEAN DEFAULT TRUE,
                is_active BOOLEAN DEFAULT TRUE,
                last_seen TIMESTAMP,
                applied_config_version VARCHAR(100),
                config_version VARCHAR(100),
                api_key VARCHAR(128),
                api_key_name VARCHAR(100),
                api_key_created_at TIMESTAMP,
                api_key_expires_at TIMESTAMP,
                api_key_last_used TIMESTAMP,
                api_key_created_by INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Create backends table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS backends (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                balance_method VARCHAR(50) DEFAULT 'roundrobin',
                mode VARCHAR(10) DEFAULT 'http',
                health_check_uri VARCHAR(255),
                health_check_interval INTEGER DEFAULT 2000,
                health_check_expected_status INTEGER DEFAULT 200,
                fullconn INTEGER,
                timeout_connect INTEGER DEFAULT 10000,
                timeout_server INTEGER DEFAULT 60000,
                timeout_queue INTEGER DEFAULT 60000,
                cluster_id INTEGER REFERENCES haproxy_clusters(id) ON DELETE CASCADE,
                maxconn INTEGER,
                last_config_status config_status DEFAULT 'APPLIED',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, cluster_id)
            );
        """)
        
        # Add new columns to existing backends table if they don't exist
        await conn.execute("""
            DO $$ 
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backends' AND column_name='health_check_expected_status') THEN
                    ALTER TABLE backends ADD COLUMN health_check_expected_status INTEGER DEFAULT 200;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backends' AND column_name='fullconn') THEN
                    ALTER TABLE backends ADD COLUMN fullconn INTEGER;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backends' AND column_name='cookie_name') THEN
                    ALTER TABLE backends ADD COLUMN cookie_name VARCHAR(100);
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backends' AND column_name='cookie_options') THEN
                    ALTER TABLE backends ADD COLUMN cookie_options TEXT;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backends' AND column_name='default_server_inter') THEN
                    ALTER TABLE backends ADD COLUMN default_server_inter INTEGER;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backends' AND column_name='default_server_fall') THEN
                    ALTER TABLE backends ADD COLUMN default_server_fall INTEGER;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backends' AND column_name='default_server_rise') THEN
                    ALTER TABLE backends ADD COLUMN default_server_rise INTEGER;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backends' AND column_name='request_headers') THEN
                    ALTER TABLE backends ADD COLUMN request_headers TEXT;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backends' AND column_name='response_headers') THEN
                    ALTER TABLE backends ADD COLUMN response_headers TEXT;
                END IF;
            END $$;
        """)
        
        # Create backend_servers table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS backend_servers (
                id SERIAL PRIMARY KEY,
                backend_id INTEGER REFERENCES backends(id) ON DELETE CASCADE,
                backend_name VARCHAR(100) NOT NULL,
                server_name VARCHAR(100) NOT NULL,
                server_address VARCHAR(255) NOT NULL,
                server_port INTEGER NOT NULL,
                weight INTEGER DEFAULT 100,
                maxconn INTEGER,
                check_enabled BOOLEAN DEFAULT TRUE,
                check_port INTEGER,
                backup_server BOOLEAN DEFAULT FALSE,
                ssl_enabled BOOLEAN DEFAULT FALSE,
                ssl_verify VARCHAR(20),
                cookie_value VARCHAR(100),
                inter INTEGER,
                fall INTEGER,
                rise INTEGER,
                cluster_id INTEGER REFERENCES haproxy_clusters(id) ON DELETE CASCADE,
                is_active BOOLEAN DEFAULT TRUE,
                last_config_status config_status DEFAULT 'APPLIED',
                haproxy_status VARCHAR(20) DEFAULT 'unknown',
                haproxy_status_updated_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(backend_id, server_name)
            );
        """)
        
        # Add new columns to existing backend_servers table if they don't exist
        await conn.execute("""
            DO $$ 
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backend_servers' AND column_name='check_port') THEN
                    ALTER TABLE backend_servers ADD COLUMN check_port INTEGER;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backend_servers' AND column_name='ssl_verify') THEN
                    ALTER TABLE backend_servers ADD COLUMN ssl_verify VARCHAR(20);
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backend_servers' AND column_name='cookie_value') THEN
                    ALTER TABLE backend_servers ADD COLUMN cookie_value VARCHAR(100);
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backend_servers' AND column_name='inter') THEN
                    ALTER TABLE backend_servers ADD COLUMN inter INTEGER;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backend_servers' AND column_name='fall') THEN
                    ALTER TABLE backend_servers ADD COLUMN fall INTEGER;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='backend_servers' AND column_name='rise') THEN
                    ALTER TABLE backend_servers ADD COLUMN rise INTEGER;
                END IF;
            END $$;
        """)
        
        # Create frontends table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS frontends (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                bind_address VARCHAR(255) DEFAULT '*',
                bind_port INTEGER NOT NULL,
                default_backend VARCHAR(100),
                mode VARCHAR(10) DEFAULT 'http',
                ssl_enabled BOOLEAN DEFAULT FALSE,
                ssl_certificate_id INTEGER,
                ssl_port INTEGER,
                ssl_cert_path VARCHAR(255),
                ssl_cert TEXT,
                ssl_verify VARCHAR(20) DEFAULT 'optional',
                acl_rules JSONB DEFAULT '[]'::jsonb,
                redirect_rules JSONB DEFAULT '[]'::jsonb,
                use_backend_rules TEXT,
                request_headers TEXT,
                response_headers TEXT,
                tcp_request_rules TEXT,
                timeout_client INTEGER,
                timeout_http_request INTEGER,
                rate_limit INTEGER,
                compression BOOLEAN DEFAULT FALSE,
                log_separate BOOLEAN DEFAULT FALSE,
                monitor_uri VARCHAR(255),
                cluster_id INTEGER REFERENCES haproxy_clusters(id) ON DELETE CASCADE,
                maxconn INTEGER,
                last_config_status config_status DEFAULT 'APPLIED',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, cluster_id)
            );
        """)
        
        # Add new column to existing frontends table if it doesn't exist
        await conn.execute("""
            DO $$ 
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='frontends' AND column_name='tcp_request_rules') THEN
                    ALTER TABLE frontends ADD COLUMN tcp_request_rules TEXT;
                END IF;
            END $$;
        """)
        
        # Create ssl_certificates table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ssl_certificates (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                primary_domain VARCHAR(255),
                certificate_content TEXT NOT NULL,
                private_key_content TEXT NOT NULL,
                chain_content TEXT,
                expiry_date TIMESTAMP,
                issuer TEXT,
                status VARCHAR(20) DEFAULT 'valid',
                fingerprint VARCHAR(128),
                days_until_expiry INTEGER DEFAULT 0,
                all_domains JSONB DEFAULT '[]'::jsonb,
                cluster_id INTEGER REFERENCES haproxy_clusters(id) ON DELETE SET NULL,
                last_config_status config_status DEFAULT 'APPLIED',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Create waf_rules table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS waf_rules (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                rule_type VARCHAR(50) NOT NULL,
                config JSONB NOT NULL DEFAULT '{}'::jsonb,
                action VARCHAR(20) DEFAULT 'deny',
                priority INTEGER DEFAULT 100,
                description TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                cluster_id INTEGER REFERENCES haproxy_clusters(id) ON DELETE CASCADE,
                last_config_status config_status DEFAULT 'APPLIED',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, cluster_id)
            );
        """)
        
        # Create user_activity_logs table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS user_activity_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action VARCHAR(100) NOT NULL,
                resource_type VARCHAR(50),
                resource_id VARCHAR(100),
                details JSONB,
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Create user_pool_access table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS user_pool_access (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                pool_id INTEGER REFERENCES haproxy_cluster_pools(id) ON DELETE CASCADE,
                access_level VARCHAR(20) DEFAULT 'read_write',
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                granted_by INTEGER REFERENCES users(id),
                is_active BOOLEAN DEFAULT TRUE,
                UNIQUE(user_id, pool_id)
            );
        """)
        
        # Create frontend_waf_rules junction table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS frontend_waf_rules (
                id SERIAL PRIMARY KEY,
                frontend_id INTEGER REFERENCES frontends(id) ON DELETE CASCADE,
                waf_rule_id INTEGER REFERENCES waf_rules(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(frontend_id, waf_rule_id)
            );
        """)
        
        # Create ssl_certificate_clusters junction table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ssl_certificate_clusters (
                id SERIAL PRIMARY KEY,
                ssl_certificate_id INTEGER REFERENCES ssl_certificates(id) ON DELETE CASCADE,
                cluster_id INTEGER REFERENCES haproxy_clusters(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ssl_certificate_id, cluster_id)
            );
        """)
        
        # Create indexes for performance
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agents_api_key ON agents(api_key) WHERE api_key IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_user_activity_logs_user_id ON user_activity_logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_user_activity_logs_created_at ON user_activity_logs(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_user_activity_logs_resource ON user_activity_logs(resource_type, resource_id);
            CREATE INDEX IF NOT EXISTS idx_config_versions_cluster_status ON config_versions(cluster_id, status);
            CREATE INDEX IF NOT EXISTS idx_config_versions_created_at ON config_versions(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_agents_pool_status ON agents(pool_id, status);
            CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen DESC);
            CREATE INDEX IF NOT EXISTS idx_backend_servers_backend_cluster ON backend_servers(backend_id, cluster_id);
            CREATE INDEX IF NOT EXISTS idx_frontend_waf_rules_frontend ON frontend_waf_rules(frontend_id);
            CREATE INDEX IF NOT EXISTS idx_frontend_waf_rules_waf ON frontend_waf_rules(waf_rule_id);
            CREATE INDEX IF NOT EXISTS idx_ssl_certificate_clusters_ssl ON ssl_certificate_clusters(ssl_certificate_id);
            CREATE INDEX IF NOT EXISTS idx_ssl_certificate_clusters_cluster ON ssl_certificate_clusters(cluster_id);
        """)
        
        logger.info("✅ Essential tables and indexes created/verified")
        
    except Exception as e:
        logger.error(f"Failed to create essential tables: {e}")
        raise

async def ensure_agents_table():
    """Ensures that all necessary tables, columns, and types exist in the database."""
    conn = None
    try:
        conn = await get_database_connection()
        
        # First, create all essential tables if they don't exist
        await create_essential_tables(conn)
        
        # Then, ensure additional columns exist in existing tables
        # Status column is already created in create_essential_tables
        logger.info("✅ Database schema initialization completed")
        
    except Exception as e:
        logger.error(f"Database schema initialization failed: {e}")
        raise
    finally:
        if conn:
            await close_database_connection(conn)

async def ensure_frontends_ssl_columns():
    """Add missing SSL columns to frontends table for proper SSL certificate support"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if ssl_certificate_id column exists
        ssl_cert_id_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'frontends' AND column_name = 'ssl_certificate_id'
            )
        """)
        
        # Check if ssl_port column exists
        ssl_port_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'frontends' AND column_name = 'ssl_port'
            )
        """)
        
        # Add missing columns
        if not ssl_cert_id_exists:
            logger.info("Adding ssl_certificate_id column to frontends table...")
            await conn.execute("""
                ALTER TABLE frontends 
                ADD COLUMN ssl_certificate_id INTEGER
            """)
            
        if not ssl_port_exists:
            logger.info("Adding ssl_port column to frontends table...")
            await conn.execute("""
                ALTER TABLE frontends 
                ADD COLUMN ssl_port INTEGER DEFAULT 443
            """)
        
        # CRITICAL NEW FEATURE: Check and add ssl_certificate_ids column for multiple SSL certificates
        # HAProxy supports multiple certificates on single bind: bind :443 ssl crt file1.pem crt file2.pem
        ssl_cert_ids_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'frontends' AND column_name = 'ssl_certificate_ids'
            )
        """)
        
        if not ssl_cert_ids_exists:
            logger.info("Adding ssl_certificate_ids JSONB column for multiple SSL certificates...")
            await conn.execute("""
                ALTER TABLE frontends 
                ADD COLUMN ssl_certificate_ids JSONB DEFAULT '[]'::jsonb
            """)
            logger.info("✅ ssl_certificate_ids column added successfully")
            
            # Migrate existing ssl_certificate_id to ssl_certificate_ids array
            logger.info("Migrating existing ssl_certificate_id values to ssl_certificate_ids array...")
            await conn.execute("""
                UPDATE frontends 
                SET ssl_certificate_ids = jsonb_build_array(ssl_certificate_id)
                WHERE ssl_certificate_id IS NOT NULL AND ssl_certificate_id > 0
            """)
            logger.info("✅ SSL certificate migration completed - single IDs converted to arrays")
        
        # AGENT UPGRADE TRACKING: Check and add upgrade status columns
        # These columns track agent self-upgrade process initiated from backend
        upgrade_status_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'agents' AND column_name = 'upgrade_status'
            )
        """)
        
        if not upgrade_status_exists:
            logger.info("Adding agent upgrade tracking columns...")
            await conn.execute("""
                ALTER TABLE agents 
                ADD COLUMN upgrade_status VARCHAR(50),
                ADD COLUMN upgrade_target_version VARCHAR(50),
                ADD COLUMN upgraded_at TIMESTAMP
            """)
            logger.info("✅ Agent upgrade tracking columns added successfully")
            logger.info("    - upgrade_status: Tracks upgrade process state (upgrading, completed, failed)")
            logger.info("    - upgrade_target_version: Version being upgraded to")
            logger.info("    - upgraded_at: Timestamp of last upgrade status change")
        
        # Update acl_rules and redirect_rules to JSONB if they're still TEXT[]
        acl_rules_type = await conn.fetchval("""
            SELECT data_type FROM information_schema.columns 
            WHERE table_name = 'frontends' AND column_name = 'acl_rules'
        """)
        
        if acl_rules_type == 'ARRAY':
            logger.info("Converting acl_rules from TEXT[] to JSONB...")
            await conn.execute("""
                ALTER TABLE frontends 
                ALTER COLUMN acl_rules TYPE JSONB USING array_to_json(acl_rules)::JSONB
            """)
            
        redirect_rules_type = await conn.fetchval("""
            SELECT data_type FROM information_schema.columns 
            WHERE table_name = 'frontends' AND column_name = 'redirect_rules'
        """)
        
        if redirect_rules_type == 'ARRAY':
            logger.info("Converting redirect_rules from TEXT[] to JSONB...")
            await conn.execute("""
                ALTER TABLE frontends 
                ALTER COLUMN redirect_rules TYPE JSONB USING array_to_json(redirect_rules)::JSONB
            """)
            
        await close_database_connection(conn)
        logger.info("✅ Frontends SSL columns migration completed")
        
    except Exception as e:
        logger.error(f"Failed to ensure frontends SSL columns: {e}")
        if conn:
            await close_database_connection(conn)
        # Don't raise - this is not critical for system operation

async def ensure_validation_error_columns():
    """
    Add validation_error columns to config_versions and agents tables
    These columns store HAProxy validation errors reported by agents
    """
    conn = None
    try:
        conn = await get_database_connection()
        
        # VALIDATION ERROR TRACKING: Add columns to config_versions table
        validation_error_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'config_versions' AND column_name = 'validation_error'
            )
        """)
        
        if not validation_error_exists:
            logger.info("Adding validation error columns to config_versions table...")
            await conn.execute("""
                ALTER TABLE config_versions 
                ADD COLUMN validation_error TEXT,
                ADD COLUMN validation_error_reported_at TIMESTAMP
            """)
            logger.info("✅ Validation error columns added to config_versions")
            logger.info("    - validation_error: Stores HAProxy validation error message from agent")
            logger.info("    - validation_error_reported_at: Timestamp when error was reported")
        else:
            logger.info("ℹ️  Validation error columns already exist in config_versions table")
        
        # VALIDATION ERROR TRACKING: Add columns to agents table
        agent_validation_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'agents' AND column_name = 'last_validation_error'
            )
        """)
        
        if not agent_validation_exists:
            logger.info("Adding validation error columns to agents table...")
            await conn.execute("""
                ALTER TABLE agents 
                ADD COLUMN last_validation_error TEXT,
                ADD COLUMN last_validation_error_at TIMESTAMP
            """)
            logger.info("✅ Validation error columns added to agents")
            logger.info("    - last_validation_error: Last HAProxy validation error encountered by this agent")
            logger.info("    - last_validation_error_at: Timestamp of last validation error")
        else:
            logger.info("ℹ️  Validation error columns already exist in agents table")
        
        logger.info("✅ Validation error columns migration completed")
        
    except Exception as e:
        logger.error(f"Failed to ensure validation error columns: {e}")
        if conn:
            await close_database_connection(conn)
        # Don't raise - this is not critical for system operation

async def ensure_agent_versions_table():
    """Create agent_versions table for managing agent script versions"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Create agent_versions table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_versions (
                id SERIAL PRIMARY KEY,
                platform VARCHAR(50) NOT NULL,
                version VARCHAR(20) NOT NULL,
                release_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                changelog TEXT[],
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(platform, version)
            )
        """)
        
        # Insert default versions for each platform
        await conn.execute("""
            INSERT INTO agent_versions (platform, version, changelog) 
            VALUES 
                ('macos', '1.0.0', ARRAY[
                    'Initial agent version with heartbeat sync fix',
                    'Complete HAProxy configuration management',
                    'SSL certificate deployment support',
                    'Zero-downtime configuration reload',
                    'Production-ready agent foundation'
                ]),
                ('linux', '1.0.0', ARRAY[
                    'Initial agent version with heartbeat sync fix',
                    'Complete HAProxy configuration management',
                    'SSL certificate deployment support',
                    'Zero-downtime configuration reload',
                    'Production-ready agent foundation'
                ])
            ON CONFLICT (platform, version) DO NOTHING
        """)
        
        await close_database_connection(conn)
        logger.info("✅ Agent versions table created successfully")
        
    except Exception as e:
        if conn:
            await close_database_connection(conn)
        logger.error(f"Error creating agent_versions table: {e}")
        # Don't raise - this is not critical for system operation

async def ensure_agent_script_templates_table():
    """Create agent_script_templates table for storing editable script templates"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Create agent_script_templates table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_script_templates (
                id SERIAL PRIMARY KEY,
                platform VARCHAR(50) NOT NULL,
                version VARCHAR(20) NOT NULL,
                script_content TEXT NOT NULL,
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(platform, version)
            )
        """)
        
        # Load initial script templates from files and sync with existing versions
        import os
        script_dir = os.path.join(os.path.dirname(__file__), '..', 'utils', 'agent_scripts')
        
        # Get current agent versions from database
        macos_version_row = await conn.fetchrow("SELECT version FROM agent_versions WHERE platform = 'macos' AND is_active = true ORDER BY created_at DESC LIMIT 1")
        linux_version_row = await conn.fetchrow("SELECT version FROM agent_versions WHERE platform = 'linux' AND is_active = true ORDER BY created_at DESC LIMIT 1")
        
        macos_current_version = macos_version_row['version'] if macos_version_row else '1.0.0'
        linux_current_version = linux_version_row['version'] if linux_version_row else '1.0.0'
        
        # Load macOS script with current version
        macos_script_path = os.path.join(script_dir, 'macos_install.sh')
        if os.path.exists(macos_script_path):
            with open(macos_script_path, 'r') as f:
                macos_script = f.read()
            
            await conn.execute("""
                INSERT INTO agent_script_templates (platform, version, script_content) 
                VALUES ('macos', $1, $2)
                ON CONFLICT (platform, version) DO UPDATE SET
                script_content = EXCLUDED.script_content,
                updated_at = CURRENT_TIMESTAMP
            """, macos_current_version, macos_script)
            
            logger.info(f"✅ Loaded macOS script template version {macos_current_version}")
        
        # Load Linux script with current version
        linux_script_path = os.path.join(script_dir, 'linux_install.sh')
        if os.path.exists(linux_script_path):
            with open(linux_script_path, 'r') as f:
                linux_script = f.read()
            
            await conn.execute("""
                INSERT INTO agent_script_templates (platform, version, script_content) 
                VALUES ('linux', $1, $2)
                ON CONFLICT (platform, version) DO UPDATE SET
                script_content = EXCLUDED.script_content,
                updated_at = CURRENT_TIMESTAMP
            """, linux_current_version, linux_script)
            
            logger.info(f"✅ Loaded Linux script template version {linux_current_version}")
        
        await close_database_connection(conn)
        logger.info("✅ Agent script templates table created successfully")
        
    except Exception as e:
        if conn:
            await close_database_connection(conn)
        logger.error(f"Error creating agent_script_templates table: {e}")
        # Don't raise - this is not critical for system operation

async def ensure_agent_config_management_tables():
    """Create tables for Configuration Management feature"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Create agent_config_requests table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_config_requests (
                id SERIAL PRIMARY KEY,
                agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
                agent_name VARCHAR(255) NOT NULL,
                request_type VARCHAR(50) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                requested_by INTEGER REFERENCES users(id),
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '5 minutes'),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create agent_config_responses table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_config_responses (
                id SERIAL PRIMARY KEY,
                request_id INTEGER REFERENCES agent_config_requests(id) ON DELETE CASCADE,
                agent_name VARCHAR(255) NOT NULL,
                config_content TEXT NOT NULL,
                config_path VARCHAR(500),
                file_size BIGINT,
                response_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '10 minutes'),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for performance
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_config_requests_agent_name 
            ON agent_config_requests(agent_name);
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_config_requests_status 
            ON agent_config_requests(status);
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_config_requests_expires_at 
            ON agent_config_requests(expires_at);
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_config_responses_request_id 
            ON agent_config_responses(request_id);
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_config_responses_expires_at 
            ON agent_config_responses(expires_at);
        """)
        
        await close_database_connection(conn)
        logger.info("✅ Agent configuration management tables created successfully")
        
    except Exception as e:
        if conn:
            await close_database_connection(conn)
        logger.error(f"Error creating agent configuration management tables: {e}")
        # Don't raise - this is not critical for system operation

async def fix_users_unique_constraints_for_soft_delete():
    """Fix users table unique constraints to support soft delete
    
    Replace table-level UNIQUE constraints with partial unique indexes
    that only apply to active users (is_active = TRUE).
    This allows soft-deleted users to be recreated with the same username/email.
    """
    conn = None
    try:
        conn = await get_database_connection()
        
        # Check if the old constraints exist
        username_constraint_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM pg_constraint 
                WHERE conname = 'users_username_key'
            )
        """)
        
        email_constraint_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM pg_constraint 
                WHERE conname = 'users_email_key'
            )
        """)
        
        # Check if partial indexes already exist
        username_index_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM pg_indexes 
                WHERE indexname = 'users_username_active_key'
            )
        """)
        
        email_index_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM pg_indexes 
                WHERE indexname = 'users_email_active_key'
            )
        """)
        
        # Drop old username constraint if exists
        if username_constraint_exists:
            logger.info("Dropping users_username_key constraint...")
            await conn.execute("ALTER TABLE users DROP CONSTRAINT users_username_key")
            logger.info("✅ Dropped users_username_key constraint")
        
        # Drop old email constraint if exists
        if email_constraint_exists:
            logger.info("Dropping users_email_key constraint...")
            await conn.execute("ALTER TABLE users DROP CONSTRAINT users_email_key")
            logger.info("✅ Dropped users_email_key constraint")
        
        # Create partial unique index for username (only active users)
        if not username_index_exists:
            logger.info("Creating partial unique index for username...")
            await conn.execute("""
                CREATE UNIQUE INDEX users_username_active_key 
                ON users(username) 
                WHERE is_active = TRUE
            """)
            logger.info("✅ Created users_username_active_key partial index")
        else:
            logger.info("ℹ️  users_username_active_key index already exists")
        
        # Create partial unique index for email (only active users)
        if not email_index_exists:
            logger.info("Creating partial unique index for email...")
            await conn.execute("""
                CREATE UNIQUE INDEX users_email_active_key 
                ON users(email) 
                WHERE is_active = TRUE
            """)
            logger.info("✅ Created users_email_active_key partial index")
        else:
            logger.info("ℹ️  users_email_active_key index already exists")
        
        logger.info("✅ Users table unique constraints fixed for soft delete support")
        
    except Exception as e:
        logger.error(f"❌ Failed to fix users unique constraints: {e}")
        raise
    finally:
        if conn:
            await close_database_connection(conn)
