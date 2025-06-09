# app/utils/message_builder.py


base_text = "За першим питанням порядку денного за проектом рішення: Затвердити звіт керівництва Товариства за 2024 рік"

def get_personalized_message(choice: str, voter_id: str) -> str:
    return f"{base_text} - {choice} - {voter_id}"
