# kzp/storage.py

from typing import Dict, Any

class SecureBallotStorage:
    def __init__(self):
        # Словник у форматі: voter_id -> дані голосу
        self._votes: Dict[str, Dict[str, Any]] = {}

    def store_vote(self, voter_id: str, vote_data: Dict[str, Any]):
        """Зберігає дані голосу для конкретного виборця"""
        self._votes[voter_id] = vote_data

    def get_vote(self, voter_id: str) -> Dict[str, Any] | None:
        """Повертає голос виборця (або None)"""
        return self._votes.get(voter_id)

    def get_all_votes(self) -> Dict[str, Dict[str, Any]]:
        """Повертає всі збережені голоси"""
        return self._votes

    def clear_votes(self):
        """Очищає всі збережені голоси"""
        self._votes.clear()

    def has_voted(self, voter_id: str) -> bool:
        """Перевіряє, чи виборець уже проголосував"""
        return voter_id in self._votes
