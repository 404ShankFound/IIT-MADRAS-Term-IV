from concrete import fhe


def compare(a, b):
    return a > b


def main():
    try:
        max_value = int(input("Largest number you may enter: "))

        compiler = fhe.Compiler(
            compare,
            {"a": "encrypted", "b": "encrypted"}
        )

        # Compile for the full range 0..max_value.
        inputset = [(a, b) for a in range(max_value + 1)
                            for b in range(max_value + 1)]
        circuit = compiler.compile(inputset)

        first = int(input("Enter the first number: "))
        second = int(input("Enter the second number: "))

        if not (0 <= first <= max_value and 0 <= second <= max_value):
            print(f"Both numbers must be between 0 and {max_value}.")
            return

        result = circuit.encrypt_run_decrypt(first, second)
        print("First number is greater:", result)

    except ValueError:
        print("Enter whole numbers only.")


if __name__ == "__main__":
    main()