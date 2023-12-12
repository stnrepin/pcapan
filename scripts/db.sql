CREATE DATABASE IF NOT EXISTS db;

CREATE TABLE IF NOT EXISTS db.pkts_queue (
    flow String,
    time UInt64,
    size UInt64,
    l2_proto String,
    l2_size UInt64,
    l3_proto String,
    l3_size UInt64,
    l4_proto String,
    l4_size UInt64,
    l7_proto String,
) ENGINE = RabbitMQ SETTINGS rabbitmq_host_port = 'localhost:5672',
                             rabbitmq_exchange_name = 'pcapan.stats',
                             rabbitmq_routing_key_list = 'pcapan.stats',
                             rabbitmq_exchange_type = 'fanout',
                             rabbitmq_format = 'JSONEachRow',
                             rabbitmq_num_consumers = 5,
                             date_time_input_format = 'best_effort';

CREATE TABLE db.pkts (
    flow String,
    time UInt64,
    size UInt64,
    l2_size UInt64,
    l2_proto String,
    l3_size UInt64,
    l3_proto String,
    l4_size UInt64,
    l4_proto String,
    l7_proto String
) ENGINE = MergeTree() ORDER BY time;

CREATE MATERIALIZED VIEW db.pkts_consumer TO db.pkts
    AS SELECT * FROM db.pkts_queue;
