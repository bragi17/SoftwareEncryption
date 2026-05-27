"""Help Center and contextual field help widgets."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from skeystudio.help import HELP_SECTIONS, HelpArticle, get_field_help, get_help_sections
from skeystudio.i18n import DEFAULT_LANGUAGE, LanguageCode, tr


class ContextHelpPanel(QWidget):
    def __init__(self, language: LanguageCode = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self.language = language
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.title = QLabel()
        self.title.setProperty("role", "pageTitle")
        self.body = QTextBrowser()
        self.body.setOpenExternalLinks(False)

        layout.addWidget(self.title)
        layout.addWidget(self.body, 1)
        self.retranslate(language)

    def retranslate(self, language: LanguageCode) -> None:
        self.language = language
        default_titles = {tr("zh-CN", "help.field_title"), tr("en-US", "help.field_title"), ""}
        if self.title.text() in default_titles:
            self.title.setText(tr(language, "help.field_title"))

    def show_field(self, field_key: str) -> None:
        self.title.setText(field_key)
        entry = get_field_help(self.language).get(field_key)
        if entry is None:
            self.body.setPlainText(tr(self.language, "help.no_field"))
            return
        self.body.setPlainText(
            "\n".join(
                (
                    entry.explanation,
                    tr(self.language, "help.required", value=entry.required),
                    tr(self.language, "help.correct_example", value=entry.correct_example),
                    tr(self.language, "help.common_wrong", value=entry.common_wrong_value),
                    tr(self.language, "help.if_wrong", value=entry.wrong_result),
                ),
            ),
        )


class HelpCenterView(QWidget):
    def __init__(self, language: LanguageCode = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self.language = language
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.section_list = QListWidget()
        self.section_list.setObjectName("help_section_list")
        self.article_list = QListWidget()
        self.article_list.setObjectName("help_article_list")
        self.body = QTextBrowser()
        self.body.setObjectName("help_article_body")
        self.body.setOpenExternalLinks(False)

        self.section_list.currentTextChanged.connect(self._show_section)
        self.article_list.currentTextChanged.connect(self._show_article)

        layout.addWidget(self.section_list, 1)
        layout.addWidget(self.article_list, 2)
        layout.addWidget(self.body, 5)
        self.retranslate(language)

    def retranslate(self, language: LanguageCode) -> None:
        self.language = language
        self.section_list.blockSignals(True)
        self.section_list.clear()
        for section_name in get_help_sections(language):
            self.section_list.addItem(QListWidgetItem(section_name))
        self.section_list.blockSignals(False)

        if self.section_list.count() > 0:
            self.section_list.setCurrentRow(0)
        else:
            self.article_list.clear()
            self.body.clear()

    def _show_section(self, section_name: str) -> None:
        self.article_list.clear()
        articles = get_help_sections(self.language).get(section_name)
        if articles is None:
            self.body.setPlainText(tr(self.language, "help.no_section"))
            return
        for article in articles:
            item = QListWidgetItem(article.title)
            item.setData(256, article.article_id)
            self.article_list.addItem(item)
        if self.article_list.count() > 0:
            self.article_list.setCurrentRow(0)

    def _show_article(self, article_title: str) -> None:
        current_section = self.section_list.currentItem()
        if current_section is None:
            return
        article = self._article_by_title(current_section.text(), article_title)
        if article is not None:
            self.body.setPlainText(f"{article.title}\n\n{article.body}")

    def _article_by_title(self, section_name: str, article_title: str) -> HelpArticle | None:
        return _article_by_title(section_name, article_title, self.language)


def _article_by_title(
    section_name: str,
    article_title: str,
    language: LanguageCode = "en-US",
) -> HelpArticle | None:
    sections = get_help_sections(language) if language != "en-US" else HELP_SECTIONS
    for article in sections.get(section_name, ()):
        if article.title == article_title:
            return article
    return None
