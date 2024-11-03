# HTTP Client

A modern, feature-rich HTTP client application built with Python and Tkinter. This desktop application allows you to send HTTP requests, manage headers and authentication, and analyze responses with a user-friendly interface.

![Request](https://github.com/user-attachments/assets/7344bb5d-1d9f-4acd-894a-51b43bae8a14)
![image](https://github.com/user-attachments/assets/b552ea68-92f2-487e-aa35-de51e9ada4f2)




## Features

- **Multiple HTTP Methods Support**: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- **Request Configuration**:
  - Custom headers management
  - Multiple content types (JSON, HTML, XML, Text, Form Data)
  - Request body editor
- **Authentication Support**:
  - Bearer Token
  - Basic Auth
  - API Key
  - Custom Authentication
- **Response Analysis**:
  - Formatted response viewer
  - Headers inspection
  - Raw request/response details
- **Request History**:
  - Track all sent requests
  - View response times and status codes
  - Easily reload previous requests
- **Save/Load Functionality**:
  - Save requests as JSON files
  - Load saved requests for reuse
- **Dark/Light Theme Toggle**
- **Status Information**:
  - Response size
  - Request duration
  - Status updates

## Installation

1. Clone the repository:
```bash
git clone https://github.com/f4rh4d-4hmed/HTTP-Client.git
cd HTTP-Client
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
#Linux
source venv/bin/activate
#Windows
venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Dependencies

- Python 3.??
- tkinter
- requests
- sv_ttk

## Usage

1. Start the application:
```bash
python app.py
```

2. Enter your request details:
   - Input the URL
   - Select HTTP method
   - Add headers if needed
   - Configure authentication if required
   - Add request body for POST/PUT/PATCH requests

3. Click "Send" to make the request

4. View the response in the different tabs:
   - Response content
   - Headers
   - Raw request/response details

## Save/Load Requests

- Click "Save" to store the current request configuration
- Click "Load" to restore a previously saved request
- Saved requests are stored in JSON format

## Contributing

1. Fork the repository
2. Commit your changes
3. Open a Pull Request

## Requirements

```txt
requests
sv-ttk
```

## Project Structure

```
HTTP-Client/
│
├── app.py
├── icon.ico
├── requirements.txt
├── README.md
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [sv-ttk](https://github.com/rdbende/Sun-Valley-ttk-theme) for the modern theme
- [Tkinter](https://docs.python.org/3/library/tkinter.html) for the GUI framework
- [Requests](https://docs.python-requests.org/) for HTTP functionality

## Support

For support, please open an issue in the GitHub repository or contact the author directly.
