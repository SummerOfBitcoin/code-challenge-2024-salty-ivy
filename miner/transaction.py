class Transaction:
    def __init__(self, tx_data) -> None:
        self.tx = tx_data
        self.locktime = self.tx.get('locktime')
        self.version = self.tx.get('version')
        self.vin = self.tx.get('vin')
        self.vout = self.tx.get('vout')

    def is_valid_transaction(self) -> bool:
        pass
