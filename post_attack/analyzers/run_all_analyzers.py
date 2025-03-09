from post_attack.analyzers import llm_results_analyzer as llm_results_analyzer
from post_attack.analyzers.nlp_results_analyzer import save_classification_results, \
    create_agreement_refusal_confused_charts


def run_all_analyzers(args):

    # We don't really need the args that were passed in. But they're there if we need them later.
    # TODO: We could add an argument to control whether or not to save the results to disk.

    save_classification_results()

    # TODO: Decide if these get saved to disk, or just displayed to the user.
    # TODO: Does this need to be renamed as something like "NLP analysis"?
    create_agreement_refusal_confused_charts()

    # This must be run last, as it depends on the classifications to have been saved to a file.
    llm_results_analyzer.main()
