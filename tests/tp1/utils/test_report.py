from unittest.mock import patch, MagicMock
from src.tp1.utils.report import Report
from src import config as project_config
import os


def test_report_init():
    # Given
    capture = MagicMock()
    filename = "test.pdf"
    summary = "Test summary"

    # When
    report = Report(capture, filename, summary)

    # Then
    assert report.capture == capture
    assert report.filename == filename
    assert report.title == "RAPPORT IDS/IPS - ANALYSE DE TRAFIC RÉSEAU"
    assert report.summary == summary
    assert report.array == ""
    assert report.graph == ""


def test_concat_report():
    # Given
    capture = MagicMock()
    report = Report(capture, "test.pdf", "Test summary")
    report.array = "Test Array"
    report.graph = "Test Graph"

    # When
    result = report.concat_report()

    # Then
    assert "RAPPORT IDS/IPS - ANALYSE DE TRAFIC RÉSEAU" in result
    assert "Test summary" in result
    assert "Test Array" in result


def test_generate_array():
    # Given
    capture = MagicMock()
    capture.sort_network_protocols.return_value = {'TCP': 25, 'UDP': 15}
    capture.attacks = []

    report = Report(capture, "test.pdf", "Test summary")

    # When
    report.generate("array")

    # Then
    assert report.array != ""
    assert "TCP" in report.array
    assert "25" in report.array
    assert "UDP" in report.array


def test_generate_array_with_attacks():
    # Given
    capture = MagicMock()
    capture.sort_network_protocols.return_value = {'TCP': 25}
    capture.attacks = [
        {'type': 'ARP Spoofing', 'src_ip': '192.168.1.1'},
        {'type': 'Port Scan', 'src_ip': '10.0.0.1'}
    ]

    report = Report(capture, "test.pdf", "Test summary")

    # When
    report.generate("array")

    # Then
    assert "ATTAQUES DÉTECTÉES" in report.array
    assert "ARP Spoofing" in report.array
    assert "192.168.1.1" in report.array


@patch('src.tp1.utils.report.pygal.Bar')
def test_generate_graph(mock_bar_chart):
    # Given
    capture = MagicMock()
    capture.sort_network_protocols.return_value = {'TCP': 25, 'UDP': 15}

    report = Report(capture, "test.pdf", "Test summary")

    # Mock the pygal chart
    mock_instance = MagicMock()
    mock_bar_chart.return_value = mock_instance

    # When
    report.generate("graph")

    # Then
    assert report.graph != ""
    mock_instance.render_to_file.assert_called_once()


def test_generate_array_empty_protocols():
    # Given
    capture = MagicMock()
    capture.sort_network_protocols.return_value = {}
    capture.attacks = []

    report = Report(capture, "test.pdf", "Test summary")

    # When
    report.generate("array")

    # Then
    assert report.array == "Aucune donnée disponible"


def test_generate_invalid_param():
    # Given
    capture = MagicMock()
    report = Report(capture, "test.pdf", "Test summary")

    # When
    report.generate("invalid")

    # Then
    # No change should occur
    assert report.graph == ""
    assert report.array == ""


# Modified test: verify TXT saving instead of PDF
def test_save_txt():
    # Given
    capture = MagicMock()
    report = Report(capture, "test.txt", "Test summary")
    report.array = "Test Array"

    # Determine expected path based on project config
    primary_basename = os.path.basename("test.txt")
    expected_primary = os.path.join(project_config.REPORT_OUTPUT_DIR, primary_basename)

    # Ensure no pre-existing files
    try:
        if os.path.exists(expected_primary):
            os.remove(expected_primary)
    except Exception:
        pass

    # When
    report.save("test.txt")

    # Then
    # The file should exist in the configured output directory
    assert os.path.exists(expected_primary)
    with open(expected_primary, "r", encoding="utf-8") as f:
        data = f.read()
    assert "RAPPORT IDS/IPS - ANALYSE DE TRAFIC RÉSEAU" in data
    assert "Test Array" in data

    # Cleanup
    try:
        os.remove(expected_primary)
    except Exception:
        pass
