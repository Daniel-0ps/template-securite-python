from unittest.mock import patch, MagicMock
from src.tp1.utils.capture import Capture
from collections import defaultdict


@patch('src.tp1.utils.capture.choose_interface', return_value='eth0')
def test_capture_init(mock_choose):
    # When
    capture = Capture()

    # Then
    assert capture.interface == 'eth0'
    assert capture.summary == ""
    assert isinstance(capture.packets, list)
    assert isinstance(capture.protocols_count, defaultdict)
    assert isinstance(capture.attacks, list)


@patch('src.tp1.utils.capture.choose_interface', return_value=None)
def test_capture_init_no_interface(mock_choose):
    # When
    capture = Capture()

    # Then
    assert capture.interface is None


@patch('src.tp1.utils.capture.choose_interface', return_value='eth0')
def test_sort_network_protocols(mock_choose):
    # Given
    capture = Capture()
    capture.protocols_count['TCP'] = 25
    capture.protocols_count['UDP'] = 15
    capture.protocols_count['ICMP'] = 8

    # When
    result = capture.sort_network_protocols()

    # Then
    assert isinstance(result, dict)
    assert result['TCP'] == 25
    # Verify sorting (descending by count)
    keys = list(result.keys())
    assert keys[0] == 'TCP'


@patch('src.tp1.utils.capture.choose_interface', return_value='eth0')
def test_get_all_protocols(mock_choose):
    # Given
    capture = Capture()
    capture.protocols_count['TCP'] = 25
    capture.protocols_count['UDP'] = 15

    # When
    result = capture.get_all_protocols()

    # Then
    assert isinstance(result, dict)
    assert result['TCP'] == 25
    assert result['UDP'] == 15


@patch('src.tp1.utils.capture.choose_interface', return_value='eth0')
def test_analyse(mock_choose):
    # Given
    capture = Capture()
    capture.protocols_count['TCP'] = 25
    capture.packets = [MagicMock(), MagicMock()]

    # When
    capture.analyse()

    # Then
    assert capture.summary != ""
    assert "Total de paquets capturés" in capture.summary


@patch('src.tp1.utils.capture.choose_interface', return_value='eth0')
def test_get_summary(mock_choose):
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


@patch('src.tp1.utils.capture.choose_interface', return_value='eth0')
def test_gen_summary(mock_choose):
    # Given
    capture = Capture()
    capture.packets = [MagicMock(), MagicMock()]
    capture.protocols_count['TCP'] = 25
    capture.attacks = []

    # When
    result = capture.gen_summary()

    # Then
    assert "Total de paquets capturés" in result
    assert "TCP" in result
    assert "Aucune attaque détectée" in result
