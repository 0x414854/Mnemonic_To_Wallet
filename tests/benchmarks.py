import timeit
import os
import sys
import logging
import pandas as pd
from dotenv import load_dotenv

# python3 tests/benchmarks.py

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mnemonicToWallet import GetUniqueMnemonic, mnemonic_to_seed, seed_to_master_key, generate_address_from_private_key

load_dotenv()

LOG_FILE = os.getenv("LOG_FILE")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

ITERATIONS = [1000, 5000, 10000, 20000, 50000, 100000]

results = []

def benchmark_function(function_name, function, *args):
    """
    Benchmark a function for the different numbers of iterations defined in ITERATIONS.

    Args:
        function_name (str): Name of the function for display/logging purposes.
        function (callable): The function to test.
        *args: Arguments to pass to the function.
    """
    for num in ITERATIONS:
        time_taken = timeit.timeit(lambda: function(*args), number=num)
        print(f"{function_name} took {time_taken:.4f} seconds for {num} iterations.")
        # logging.info(f"{function_name} took {time_taken:.6f} seconds for {num} iterations.")
        
        results.append({"Function": function_name, "Iterations": num, "Time (s)": time_taken})

def main(): 
    len_seeds = [12, 24]
    benchmark_function("GetUniqueMnemonic", GetUniqueMnemonic, len_seeds)

    mnemonic = GetUniqueMnemonic(len_seeds)
    passphrase = ""
    benchmark_function("mnemonic_to_seed", mnemonic_to_seed, mnemonic, passphrase)

    seed = b"0" * 64
    benchmark_function("seed_to_master_key", seed_to_master_key, seed)

    private_key = b"1" * 32
    benchmark_function("generate_address_from_private_key", generate_address_from_private_key, private_key)

    df = pd.DataFrame(results)
    print("\nBenchmark Results :")
    print(df)

    results_file = "./tests/benchmark_results.csv"
    df.to_csv(results_file, index=False)
    print(f"\nBenchmark results saved to {results_file}.")
    logging.info(f"Benchmark results saved to {results_file}.")



if __name__ == "__main__":
    main()