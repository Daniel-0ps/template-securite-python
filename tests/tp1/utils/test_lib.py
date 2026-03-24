from src.tp1.utils.lib import hello_world, choose_interface
from unittest.mock import patch


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


@patch('builtins.input', return_value='1')
@patch('scapy.arch.get_if_list', return_value=['eth0', 'wlan0'])
def test_when_choose_interface_with_valid_choice_then_return_interface(mock_get_if, mock_input):
    # When
    result = choose_interface()

    # Then
    assert result == 'eth0'


@patch('builtins.input', side_effect=['999', 'invalid', '2'])
@patch('scapy.arch.get_if_list', return_value=['eth0', 'wlan0'])
def test_when_choose_interface_with_invalid_choice_then_retry(mock_get_if, mock_input):
    # When
    result = choose_interface()

    # Then
    assert result == 'wlan0'
