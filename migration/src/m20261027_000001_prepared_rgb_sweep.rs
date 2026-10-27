use sea_orm_migration::{prelude::*, sea_orm::ConnectionTrait};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(
            "CREATE TABLE prepared_rgb_sweep (batch_transfer_idx INTEGER PRIMARY KEY NOT NULL REFERENCES batch_transfer(idx) ON DELETE RESTRICT, txid TEXT NOT NULL UNIQUE, phase TEXT NOT NULL CHECK (phase IN ('prepared', 'handed_off', 'consumed', 'cancelled')), payload BLOB NOT NULL, payload_sha256 TEXT NOT NULL)"
        ).await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Downgrading would discard the only durable ownership proof for an externally signed
        // transaction. Even a terminal record is an identity tombstone, so never drop it silently.
        let row = manager
            .get_connection()
            .query_one_raw(sea_orm::Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT count(*) AS count FROM prepared_rgb_sweep".to_owned(),
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("missing prepared sweep count".into()))?;
        let count: i64 = row.try_get("", "count")?;
        if count != 0 {
            return Err(DbErr::Custom(
                "cannot remove retained prepared RGB sweep records".into(),
            ));
        }
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE prepared_rgb_sweep")
            .await?;
        Ok(())
    }
}
