import pytest
from ibc_monitor.filters import PacketFilter, ExcludedSequences

@pytest.fixture
def pf():
    return PacketFilter('allow', [['a*','c*'],['b','d']])

def test_packet_filter_allow(pf):
    assert pf.matches('abc','cdf')
    assert pf.matches('b','d')
    assert not pf.matches('x','y')

def test_packet_filter_deny():
    pf2 = PacketFilter('deny',[['x*','y*']])
    assert not pf2.matches('x1','y1')
    assert pf2.matches('a','b')

def test_excluded_sequences():
    ex = ExcludedSequences({'ch':[1,'2-3']})
    assert ex.is_excluded('ch',1)
    assert ex.is_excluded('ch',2)
    assert not ex.is_excluded('ch',4)