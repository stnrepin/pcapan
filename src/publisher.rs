use amqprs::{
    callbacks::{DefaultChannelCallback, DefaultConnectionCallback},
    channel::{BasicPublishArguments, Channel, QueueBindArguments, QueueDeclareArguments},
    connection::{Connection, OpenConnectionArguments},
    BasicProperties,
};
use tokio::time;

pub struct Publisher {
    connection: Connection,
    channel: Channel,
    queue_name: String,
}

impl Publisher {
    const ROUTING_KEY: &'static str = "pcapan.stats";
    const QUEUE: &'static str = "pcapan.stats";
    const EXCHANGE_NAME: &'static str = "pcapan.stats";

    pub async fn connect(
        addr: &str,
        port: u16,
        user_name: &str,
        password: &str,
    ) -> Result<Self, String> {
        let connection = Connection::open(&OpenConnectionArguments::new(
            addr, port, user_name, password,
        ))
        .await
        .map_err(|err| format!("rmq error (open): {}", err.to_string()))?;

        connection
            .register_callback(DefaultConnectionCallback)
            .await
            .map_err(|err| format!("rmq error (open): {}", err.to_string()))?;

        let channel = connection.open_channel(None).await.unwrap();
        channel
            .register_callback(DefaultChannelCallback)
            .await
            .map_err(|err| format!("rmq error (channel): {}", err.to_string()))?;

        let (queue_name, _, _) = channel
            .queue_declare(QueueDeclareArguments::durable_client_named(Self::QUEUE))
            .await
            .map_err(|err| format!("rmq error (queue): {}", err.to_string()))?
            .unwrap();

        channel
            .queue_bind(QueueBindArguments::new(
                &queue_name,
                Self::EXCHANGE_NAME,
                Self::ROUTING_KEY,
            ))
            .await
            .map_err(|err| format!("rmq error (queue_bind): {}", err.to_string()))?;

        Ok(Publisher {
            connection,
            channel,
            queue_name,
        })
    }

    pub async fn send(&self, data: Vec<u8>) -> Result<(), String> {
        let args = BasicPublishArguments::new(Self::EXCHANGE_NAME, Self::ROUTING_KEY);
        self.channel
            .basic_publish(BasicProperties::default(), data, args)
            .await
            .unwrap();

        Ok(())
    }

    pub async fn wait_all_sends(&self) {
        time::sleep(time::Duration::from_millis(500)).await;
    }
}
