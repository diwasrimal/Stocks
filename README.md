# Stocks
A place to buy and sell stocks made using Flask

Implemented with the help of [Finance](https://cs50.harvard.edu/x/2022/psets/9/finance/)

## Getting Started
Stocks are managed by querying [IEX](https://exchange.iex.io/products/market-data-connectivity/) for stocks’ prices.

Get your API key via [here](https://iexcloud.io/console/tokens)

## Configuration
Install [python](https://www.python.org/)

### Set up a virtual environment
#### macOS/Linux
```bash
cd stocks
python3 -m venv venv
```
#### Windows
```cmd
cd stocks
python3 -m venv venv
```
### Run Scripts

#### macOS/Linux
```bash
. venv/bin/activate
```
#### Windows
```cmd
venv\Scripts\activate

```
### Install Flask
```bash
pip install Flask
```

### Install project requirements
```bash
pip install -r requirements.txt
```
### Set API key
#### Bash
```bash
export API_KEY=value
```
#### Command Prompt
```cmd
set API_KEY=value
```

## Run using
```bash
flask run
```



