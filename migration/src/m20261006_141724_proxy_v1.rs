use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Encryption::Unsupported (see database::enums::Encryption), default for pre-update transfers, which
// had no encryption.
const ENCRYPTION_UNSUPPORTED: i32 = 2;
// TransportEndpointKind::RecipientProxy (see database::enums::TransportEndpointKind), default for
// pre-existing transfer transport endpoints, which were all recipient proxies.
const KIND_RECIPIENT_PROXY: i32 = 1;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Transfer::Table)
                    .add_column(
                        ColumnDef::new(Transfer::RecipientPubkey)
                            .binary_len(32)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Transfer::Table)
                    .add_column(ColumnDef::new(Transfer::ConsignmentHash).string().null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Transfer::Table)
                    .add_column(
                        ColumnDef::new(Transfer::RecipientEncryption)
                            .tiny_unsigned()
                            .not_null()
                            .default(ENCRYPTION_UNSUPPORTED),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Transfer::Table)
                    .add_column(ColumnDef::new(Transfer::AckSignature).binary_len(64).null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Transfer::Table)
                    .add_column(ColumnDef::new(Transfer::ProxyTransferId).string().null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Transfer::Table)
                    .add_column(
                        ColumnDef::new(Transfer::InvoiceExpiration)
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(BatchTransfer::Table)
                    .add_column(
                        ColumnDef::new(BatchTransfer::OperationSecretKey)
                            .binary_len(32)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(BatchTransfer::Table)
                    .add_column(
                        ColumnDef::new(BatchTransfer::BroadcastDeadline)
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(TransferTransportEndpoint::Table)
                    .add_column(
                        ColumnDef::new(TransferTransportEndpoint::Kind)
                            .tiny_unsigned()
                            .not_null()
                            .default(KIND_RECIPIENT_PROXY),
                    )
                    .to_owned(),
            )
            .await?;
        // the same proxy URL can now appear for one transfer in two roles (recipient vs sender), so
        // the uniqueness must also account for the endpoint kind
        manager
            .drop_index(
                Index::drop()
                    .name("idx-tte-transferidx-transportendpointidx")
                    .table(TransferTransportEndpoint::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx-tte-transferidx-transportendpointidx-kind")
                    .table(TransferTransportEndpoint::Table)
                    .col(TransferTransportEndpoint::TransferIdx)
                    .col(TransferTransportEndpoint::TransportEndpointIdx)
                    .col(TransferTransportEndpoint::Kind)
                    .unique()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for col in [
            Transfer::RecipientPubkey,
            Transfer::ConsignmentHash,
            Transfer::RecipientEncryption,
            Transfer::AckSignature,
            Transfer::ProxyTransferId,
            Transfer::InvoiceExpiration,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Transfer::Table)
                        .drop_column(col)
                        .to_owned(),
                )
                .await?;
        }
        for col in [
            BatchTransfer::OperationSecretKey,
            BatchTransfer::BroadcastDeadline,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(BatchTransfer::Table)
                        .drop_column(col)
                        .to_owned(),
                )
                .await?;
        }
        manager
            .drop_index(
                Index::drop()
                    .name("idx-tte-transferidx-transportendpointidx-kind")
                    .table(TransferTransportEndpoint::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx-tte-transferidx-transportendpointidx")
                    .table(TransferTransportEndpoint::Table)
                    .col(TransferTransportEndpoint::TransferIdx)
                    .col(TransferTransportEndpoint::TransportEndpointIdx)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(TransferTransportEndpoint::Table)
                    .drop_column(TransferTransportEndpoint::Kind)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Transfer {
    Table,
    RecipientPubkey,
    ConsignmentHash,
    RecipientEncryption,
    AckSignature,
    ProxyTransferId,
    InvoiceExpiration,
}

#[derive(DeriveIden)]
enum BatchTransfer {
    Table,
    OperationSecretKey,
    BroadcastDeadline,
}

#[derive(DeriveIden)]
enum TransferTransportEndpoint {
    Table,
    Kind,
    TransferIdx,
    TransportEndpointIdx,
}
