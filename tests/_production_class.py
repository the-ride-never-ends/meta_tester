


class ProductionClass:
    """A sample production class with methods to be tested."""

    def __init__(self):
        self.public_attribute = 0
        self._private_attribute = "private"

    @property
    def public_property(self) -> int:
        return self.public_attribute

    @property
    def _private_property(self) -> str:
        return self._private_attribute

    def production_method(self, x: int, y: int) -> int:
        return x + y

    def another_production_method(self, text: str) -> str:
        return text.upper()

    def _private_method(self) -> str:
        return "This is a private method"
