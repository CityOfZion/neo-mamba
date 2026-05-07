class Rectangle:
    def __init__(self: Rectangle, width: int, height: int) -> None:
        self.width: int = width
        self.height: int = height

    def area(self: Rectangle) -> int:
        return self.width * self.height

    def perimeter(self: Rectangle) -> int:
        return (self.width + self.height) * 2
